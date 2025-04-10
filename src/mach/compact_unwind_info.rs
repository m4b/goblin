//! Support for the "compact unwinding format" used by Apple platforms,
//! which can be found in __unwind_info sections of binaries.
//!
//! The primary type of interest is CompactUnwindInfoIter, which can be
//! constructed from a CompactUnwindInfo, which can be constructed from
//! a UnwindInfoFrame.
//!
//! The CompactUnwindInfoIter lets you iterate through all of the mappings
//! from instruction addresses to unwinding instructions, or lookup a specific
//! mapping by instruction address.
//!
//! Example:
//!
//! ```rust,ignore
//! fn process_dwarf<'d: 'o, 'o, O>(&mut self, object: &O) -> error::Result<(), CfiError>
//!     where
//!         O: ObjectLike<'d, 'o> + Dwarf<'o>,
//! {
//!     let endian = object.endianity();
//!     if let Some(section) = object.section("unwind_info") {
//!         let frame = UnwindInfoFrame::new(&section.data, endian);
//!         let info = CompactUnwindInfo::new(object, section.address, frame);
//!
//!         let mut iter = info.iter()?;
//!         while let Some(entry) = iter.next()? {
//!             let base_address = entry.instruction_address;
//!             let len = entry.len;
//!             if let Some(instructions) = entry.cfi_instructions(&iter) {
//!                 for instruction in instructions {
//!                     // Interpret the CFI instructions
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! # Unimplemented Features (TODO)
//!
//! * ARM64 opcode decoding (and writing the section on that format)
//! * Personality/LSDA lookup (for runtime unwinders)
//! * Entry lookup by address (for runtime unwinders)
//! * x86/x64 Stackless-Indirect mode decoding (for stack frames > 2KB)
//! * x86/x64 DWARF mode decoding (for when compact unwinding defers to the DWARF in eh_frame)
//!
//!
//! # The Compact Unwinding Format
//!
//! This format is defined only by its implementation in llvm. Notably these two
//! files include lots of useful comments and definitions:
//!
//! * [Header describing layout of the format](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
//! * [Implementation that outputs the format](https://github.com/llvm/llvm-project/blob/main/lld/MachO/UnwindInfoSection.cpp)
//! * [Implementation of lldb interpreting that format (CreateUnwindPlan_x86_64 especially useful)](https://github.com/llvm/llvm-project/blob/main/lldb/source/Symbol/CompactUnwindInfo.cpp)
//!
//! This implementation is based on those files at commit `d480f968ad8b56d3ee4a6b6df5532d485b0ad01e`.
//!
//! Unfortunately the description of the format in those files elides some important
//! details, and it uses some naming conventions that are confusing, so this document
//! will attempt to define this format more completely, and with more clear terms.
//!
//! Some notable terminology changes from llvm:
//!
//! * "encoding" or "encoding type" => opcode
//! * "function offset" => instruction address
//!
//! Like all unwinding info formats, the goal of the compact unwinding format
//! is to create a mapping from addresses in the binary to opcodes describing
//! how to unwind from that location.
//!
//! These opcodes describe:
//!
//! * How to recover the return pointer for the current frame
//! * How to recover some of the registers for the current frame
//! * How to run destructors / catch the unwind at runtime (personality/LSDA)
//!
//! A user of the compact unwinding format would:
//!
//! 1. Get the current instruction pointer (e.g. `%rip`).
//! 2. Lookup the corresponding opcode in the compact unwinding structure.
//! 3. Follow the instructions of that opcode to recover the current frame.
//! 4. Optionally perform runtime unwinding tasks for the current frame (destructors).
//! 5. Use that information to recover the instruction pointer of the previous frame.
//! 6. Repeat until unwinding is complete.
//!
//! The compact unwinding format can be understood as two separate pieces:
//!
//! * An architecture-agnostic "page-table" structure for finding opcode entries
//! * Architecture-specific opcode formats (x86, x64, and ARM64)
//!
//! Unlike DWARF CFI, compact unwinding doesn't have facilities for incrementally
//! updating how to recover certain registers as the function progresses.
//!
//! Empirical analysis suggests that there tends to only be one opcode for
//! an entire function (which explains why llvm refers to instruction addresses
//! as "function offsets"), although nothing in the format seems to *require*
//! this to be the case.
//!
//! One consequence of only having one opcode for a whole function is that
//! functions will generally have incorrect instructions for the function's
//! prologue (where callee-saved registers are individually PUSHed onto the
//! stack before the rest of the stack space is allocated).
//!
//! Presumably this isn't a very big deal, since there's very few situations
//! where unwinding would involve a function still executing its prologue.
//! This might matter when handling a stack overflow that occurred while
//! saving the registers, or when processing a non-crashing thread in a minidump
//! that happened to be in its prologue.
//!
//! Similarly, the way ranges of instructions are mapped means that Compact
//! Unwinding will generally incorrectly map the padding bytes between functions
//! (attributing them to the previous function), while DWARF CFI tends to more
//! more carefully exclude those addresses. Presumably also not a big deal.
//!
//! Both of these things mean that if DWARF CFI and Compact Unwinding are
//! available for a function, the DWARF CFI is expected to be more precise.
//!
//! It's possible that LSDA entries have addresses decoupled from the primary
//! opcode so that instructions on how to run destructors can vary more
//! granularly, but LSDA support is still TODO as it's not needed for
//! backtraces.
//!
//!
//! ## Page Tables
//!
//! This section describes the architecture-agnostic layout of the compact
//! unwinding format. The layout of the format is a two-level page-table
//! with one root first-level node pointing to arbitrarily many second-level
//! nodes, which in turn can hold several hundred opcode entries.
//!
//! There are two high-level concepts in this format that enable significant
//! compression of the tables:
//!
//! 1. Eliding duplicate function offsets
//! 2. Palettizing the opcodes
//!
//! Trick 1 is standard for unwinders: the table of mappings is sorted by
//! address, and any entries that would have the same opcode as the
//! previous one are elided. So for instance the following:
//!
//! ```
//! address: 1, opcode: 1
//! address: 2, opcode: 1
//! address: 3, opcode: 2
//! ```
//!
//! Is just encoded like this:
//!
//! ```
//! address: 1, opcode: 1
//! address: 3, opcode: 2
//! ```
//!
//! Trick 2 is more novel: At the first level a global palette of up to 127 opcodes
//! is defined. Each second-level "compressed" (leaf) page can also define up to 128 local
//! opcodes. Then the entries mapping function offsets to opcodes can use 8-bit
//! indices into those palettes instead of entire 32-bit opcodes. If an index is
//! smaller than the number of global opcodes, it's global, otherwise it's local
//! (subtract the global count to get the local index).
//!
//! > Unclear detail: If the global palette is smaller than 127, can the local
//!   palette be larger than 128?
//!
//! To compress these entries into a single 32-bit value, the address is truncated
//! to 24 bits and packed with the index. The addresses stored in these entries
//! are also relative to a base address that each second-level page defines.
//! (This will be made more clear below).
//!
//! There are also non-palletized "regular" second-level pages with absolute
//! 32-bit addresses, but those are fairly rare. llvm seems to only want to emit
//! them in the final page.
//!
//! The root page also stores the first address mapped by each second-level
//! page, allowing for more efficient binary search for a particular function
//! offset entry. (This is the base address the compressed pages use.)
//!
//! The root page also seems to always have a sentinel entry which has a null
//! pointer to its second-level page, but does specify a first address, which
//! makes it easy to lookup the maximum mapped address (the sentinel will store
//! that value +1).
//!
//!
//!
//! # Layout of the Page Table
//!
//! The page table starts at the very beginning of the __unwind_info section
//! with the root page:
//!
//! ```rust,ignore
//! struct RootPage {
//!   /// Only version 1 is currently defined
//!   version: u32 = 1,
//!
//!   /// The array of u32 global opcodes (offset relative to start of root page).
//!   ///
//!   /// These may be indexed by "compressed" second-level pages.
//!   global_opcodes_offset: u32,
//!   global_opcodes_len: u32,
//!
//!   /// The array of u32 global personality codes
//!   /// (offset relative to start of root page).
//!   ///
//!   /// Personalities define the style of unwinding that an unwinder should
//!   /// use, and how to interpret the LSDA entries for a function (see below).
//!   personalities_offset: u32,
//!   personalities_len: u32,
//!
//!   /// The array of FirstLevelPageEntry's describing the second-level pages
//!   /// (offset relative to start of root page).
//!   pages_offset: u32,
//!   pages_len: u32,
//!
//!   // After this point there are several dynamically-sized arrays whose
//!   // precise order and positioning don't matter, because they are all
//!   // accessed using offsets like the ones above. The arrays are:
//!
//!   global_opcodes: [u32; global_opcodes_len],
//!   personalities: [u32; personalities_len],
//!   pages: [FirstLevelPageEntry; pages_len],
//!
//!   /// An array of LSDA pointers (Language Specific Data Areas).
//!   ///
//!   /// LSDAs are tables that an unwinder's personality function will use to
//!   /// find what destructors should be run and whether unwinding should
//!   /// be caught and normal execution resumed. We can treat them opaquely.
//!   ///
//!   /// Second-level pages have addresses into this array so that it can
//!   /// can be indexed, the root page doesn't need to know about them.
//!   lsdas: [LsdaEntry; unknown_len],
//! }
//!
//!
//! struct FirstLevelPageEntry {
//!   /// The first address mapped by this page.
//!   ///
//!   /// This is useful for binary-searching for the page that can map
//!   /// a specific address in the binary (the primary kind of lookup
//!   /// performed by an unwinder).
//!   first_address: u32,
//!
//!   /// Offset to the second-level page (offset relative to start of root page).
//!   ///
//!   /// This may point to a RegularSecondLevelPage or a CompactSecondLevelPage.
//!   /// Which it is can be determined by the 32-bit "kind" value that is at
//!   /// the start of both layouts.
//!   second_level_page_offset: u32,
//!
//!   /// Base offset into the lsdas array that entries in this page will be
//!   /// relative to (offset relative to start of root page).
//!   lsda_index_offset: u32,
//! }
//!
//!
//! struct RegularSecondLevelPage {
//!   /// Always 2 (use to distinguish from CompressedSecondLevelPage).
//!   kind: u32 = 2,
//!
//!   /// The Array of RegularEntry's (offset relative to **start of this page**).
//!   entries_offset: u16,
//!   entries_len: u16,
//! }
//!
//!
//! struct RegularEntry {
//!   /// The address in the binary for this entry (absolute).
//!   instruction_address: u32,
//!   /// The opcode for this address.
//!   opcode: u32,
//! }
//!
//! struct CompressedSecondLevelPage {
//!   /// Always 3 (use to distinguish from RegularSecondLevelPage).
//!   kind: u32 = 3,
//!
//!   /// The array of compressed u32 entries
//!   /// (offset relative to **start of this page**).
//!   ///
//!   /// Entries are a u32 that contains two packed values (from high to low):
//!   /// * 8 bits: opcode index
//!   ///   * 0..global_opcodes_len => index into global palette
//!   ///   * global_opcodes_len..255 => index into local palette
//!   ///     (subtract global_opcodes_len to get the real local index)
//!   /// * 24 bits: instruction address
//!   ///   * address is relative to this page's first_address!
//!   entries_offset: u16,
//!   entries_len: u16,
//!
//!   /// The array of u32 local opcodes for this page
//!   /// (offset relative to **start of this page**).
//!   local_opcodes_offset: u16,
//!   local_opcodes_len: u16,
//! }
//!
//!
//! // TODO: why do these have instruction_addresses? Are they not in sync
//! // with the second-level entries?
//! struct LsdaEntry {
//!   instruction_address: u32,
//!   lsda_address: u32,
//! }
//! ```
//!
//!
//!
//! # Opcode Format
//!
//! There are 3 architecture-specific opcode formats: x86, x64, and ARM64.
//!
//! All 3 formats share a common header in the top 8 bits (from high to low):
//!
//! ```rust,ignore
//! /// Whether this instruction is the start of a function.
//! is_start: u1,
//!
//! /// Whether there is an lsda entry for this instruction.
//! has_lsda: u1,
//!
//! /// An index into the global personalities array
//! /// (TODO: ignore if has_lsda == false?)
//! personality_index: u2,
//!
//! /// The architecture-specific kind of opcode this is, specifying how to
//! /// interpret the remaining 24 bits of the opcode.
//! opcode_kind: u4,
//! ```
//!
//!
//! ## x86 and x64 Opcodes
//!
//! x86 and x64 use the same opcode layout, differing only in the registers
//! being restored. Registers are numbered 0-6, with the following mappings:
//!
//! x86:
//! * 0 => no register (like Option::None)
//! * 1 => ebx
//! * 2 => ecx
//! * 3 => edx
//! * 4 => edi
//! * 5 => esi
//! * 6 => ebp
//!
//! x64:
//! * 0 => no register (like Option::None)
//! * 1 => rbx
//! * 2 => r12
//! * 3 => r13
//! * 4 => r14
//! * 5 => r15
//! * 6 => rbp
//!
//! Note also that encoded sizes/offsets are generally divided by the pointer size
//! (since all values we are interested in are pointer-aligned), which of course differs
//! between x86 and x64.
//!
//! There are 5 kinds of x86/x64 opcodes (specified by opcode_kind):
//!
//!
//! ### x86 Opcode Mode 0: Old
//!
//! TODO: I don't know what this is, lldb seems to ignore it?
//!
//!
//!
//! ### x86 Opcode Mode 1: BP-Based
//!
//! The function has the standard bp-based prelude which:
//!
//! * Pushes the caller's bp (frame pointer) to the stack
//! * Sets bp = sp (new frame pointer is the current top of the stack)
//!
//! bp has been preserved, and any callee-saved registers that need to be restored
//! are saved on the stack at a known offset from bp.
//!
//! The return address is stored just before the caller's bp. The caller's stack
//! pointer should point before where the return address is saved.
//!
//! Registers are stored in increasing order (so `reg1` comes before `reg2`).
//!
//! If a register has the "no register" value, continue iterating the offset
//! forward. This lets the registers be stored slightly-non-contiguously on the
//! stack.
//!
//! The remaining 24 bits of the opcode are interpreted as follows (from high to low):
//!
//! ```rust,ignore
//! /// Registers to restore (see register mapping above)
//! reg1: u3,
//! reg2: u3,
//! reg3: u3,
//! reg4: u3,
//! reg5: u3,
//! _unused: u1,
//!
//! /// The offset from bp that the registers to restore are saved at,
//! /// divided by pointer size.
//! stack_offset: u8,
//! ```
//!
//!
//!
//! ### x86 Opcode Mode 2: Frameless (Stack-Immediate)
//!
//! The callee's stack frame has a known size, so we can find the start
//! of the frame by offsetting from sp (the stack pointer). Any callee-saved
//! registers that need to be restored are saved at the start of the stack
//! frame.
//!
//! The return address is saved immediately before the start of this frame. The
//! caller's stack pointer should point before where the return address is saved.
//!
//! Registers are stored in *reverse* order on the stack from the order the
//! decoding algorithm outputs (so `reg[1]` comes before `reg[0]`).
//!
//! If a register has the "no register" value, *do not* continue iterating the
//! offset forward -- registers are strictly contiguous (it's possible
//! "no register" can only be trailing due to the encoding, but I haven't
//! verified this).
//!
//!
//! The remaining 24 bits of the opcode are interpreted as follows (from high to low):
//!
//! ```rust,ignore
//! /// How big the stack frame is, divided by pointer size.
//! stack_size: u8,
//!
//! _unused: u3,
//!
//! /// The number of registers that are saved on the stack.
//! register_count: u3,
//!
//! /// The permutation encoding of the registers that are saved
//! /// on the stack (see below).
//! register_permutations: u10,
//! ```
//!
//! The register permutation encoding is a Lehmer code sequence encoded into a
//! single variable-base number so we can encode the ordering of up to
//! six registers in a 10-bit space.
//!
//! This can't really be described well with anything but code, so
//! just read this implementation or llvm's implementation for how to
//! encode/decode this.
//!
//!
//!
//! ### x86 Opcode Mode 3: Frameless (Stack-Indirect)
//!
//! (Currently Unimplemented)
//!
//! Stack-Indirect is exactly the same situation as Stack-Immediate, but the
//! the stack-frame size is too large for Stack-Immediate to encode. However,
//! the function prereserved the size of the frame in its prologue, so we can
//! extract the the size of the frame from a `sub` instruction at a known
//! offset from the start of the function (`subl $nnnnnnnn,ESP` in x86,
//! `subq $nnnnnnnn,RSP` in x64).
//!
//! This requires being able to find the first instruction of the function
//! (TODO: presumably the first is_start entry <= this one?).
//!
//! TODO: describe how to extract the value from the `sub` instruction.
//!
//!
//! ```rust,ignore
//! /// Offset from the start of the function where the `sub` instruction
//! /// we need is stored. (NOTE: not divided by anything!)
//! instruction_offset: u8,
//!
//! /// An offset to add to the loaded stack size, divided by pointer size.
//! /// This allows the stack size to differ slightly from the `sub`, to
//! /// compensate for any function prologue that pushes a bunch of
//! /// pointer-sized registers.
//! stack_adjust: u3,
//!
//! /// The number of registers that are saved on the stack.
//! register_count: u3,
//!
//! /// The permutation encoding of the registers that are saved on the stack
//! /// (see Stack-Immediate for a description of this format).
//! register_permutations: u10,
//! ```
//!
//! **Note**: apparently binaries generated by the clang in Xcode 6 generated
//! corrupted versions of this opcode, but this was fixed in Xcode 7
//! (released in September 2015), so *presumably* this isn't something we're
//! likely to encounter. But if you encounter messed up opcodes this might be why.
//!
//!
//!
//! ### x86 Opcode Mode 4: Dwarf
//!
//! (Currently only partially implemented)
//!
//! There is no compact unwind info here, and you should instead use the
//! DWARF CFI in .eh_frame for this line. The remaining 24 bits of the opcode
//! are an offset into the .eh_frame section that should hold the DWARF FDE
//! for this line.
//!
//!
//!
//! ## ARM64 Opcodes
//!
//! (Currently unimplemented)
//!
//! TODO: write this section
//!
//! ```text
//! kind:
//!   4=frame-based, 3=DWARF, 2=frameless
//!
//!  frameless:
//!        12-bits of stack size
//!  frame-based:
//!        4-bits D reg pairs saved
//!        5-bits X reg pairs saved
//!  DWARF:
//!        24-bits offset of DWARF FDE in __eh_frame section
//!
//! ```

use crate::error::{self, Error};
use crate::mach::segment::SectionData;
use std::mem;
use scroll::{Pread, Endian};

#[derive(Debug, Clone)]
enum Arch {
    X86,
    X64,
    Arm64,
    Other,
}

/// An iterator over the CompactUnwindInfoEntry's of a `.unwind_info` section.
#[derive(Debug, Clone)]
pub struct CompactUnwindInfoIter<'a> {
    /// Parent .unwind_info metadata.
    arch: Arch,
    endian: Endian,
    section: SectionData<'a>,
    /// Parsed root page.
    root: FirstLevelPage,

    // Iterator state

    /// Current index in the root node.
    first_idx: u32,
    /// Current index in the second-level node.
    second_idx: u32,
    /// Parsed version of the current pages.
    page_of_next_entry: Option<(FirstLevelPageEntry, SecondLevelPage)>,
    /// Minimally parsed version of the next entry, which we need to have
    /// already loaded to know how many instructions the previous entry covered.
    next_entry: Option<RawCompactUnwindInfoEntry>,
    done_page: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Pread)]
struct FirstLevelPage {
    // Only version 1 is currently defined
    // version: u32 = 1,

    /// The array of u32 global opcodes (offset relative to start of root page).
    ///
    /// These may be indexed by "compressed" second-level pages.
    global_opcodes_offset: u32,
    global_opcodes_len: u32,

    /// The array of u32 global personality codes (offset relative to start of root page).
    ///
    /// Personalities define the style of unwinding that an unwinder should use,
    /// and how to interpret the LSDA entries for a function (see below).
    personalities_offset: u32,
    personalities_len: u32,

    /// The array of FirstLevelPageEntry's describing the second-level pages
    /// (offset relative to start of root page).
    pages_offset: u32,
    pages_len: u32,


    // After this point there are several dynamically-sized arrays whose precise
    // order and positioning don't matter, because they are all accessed using
    // offsets like the ones above. The arrays are:

    // global_opcodes: [u32; global_opcodes_len],
    // personalities: [u32; personalities_len],
    // pages: [FirstLevelPageEntry; pages_len],
    // lsdas: [LsdaEntry; unknown_len],
}

/// A Compact Unwind Info entry.
#[derive(Debug, Clone)]
pub struct CompactUnwindInfoEntry {
    /// The first instruction this entry covers.
    pub instruction_address: u32,
    /// How many addresses this entry covers.
    pub len: u32,
    /// The opcode for this entry.
    opcode: Opcode,
}

#[derive(Debug, Clone)]
struct RawCompactUnwindInfoEntry {
    /// The address of the first instruction this entry applies to
    /// (may apply to later instructions as well).
    instruction_address: u32,
    /// Either an opcode or the index into an opcode palette
    opcode_or_index: OpcodeOrIndex,
}

#[derive(Debug, Clone)]
enum OpcodeOrIndex {
    Opcode(u32),
    Index(u32),
}

#[repr(C)]
#[derive(Debug, Clone, Pread)]
struct FirstLevelPageEntry {
    /// The first address mapped by this page.
    ///
    /// This is useful for binary-searching for the page that can map
    /// a specific address in the binary (the primary kind of lookup
    /// performed by an unwinder).
    first_address: u32,

    /// Offset to the second-level page (offset relative to start of root page).
    ///
    /// This may point to either a RegularSecondLevelPage or a CompactSecondLevelPage.
    /// Which it is can be determined by the 32-bit "kind" value that is at
    /// the start of both layouts.
    second_level_page_offset: u32,

    /// Base offset into the lsdas array that entries in this page will be relative
    /// to (offset relative to start of root page).
    lsda_index_offset: u32,
}

#[derive(Debug, Clone)]
enum SecondLevelPage {
    Compressed(CompressedSecondLevelPage),
    Regular(RegularSecondLevelPage),
}

#[repr(C)]
#[derive(Debug, Clone, Pread)]
struct RegularSecondLevelPage {
    // Always 2 (use to distinguish from CompressedSecondLevelPage).
    // kind: u32 = 2,

    /// The Array of RegularEntry's (offset relative to **start of this page**).
    entries_offset: u16,
    entries_len: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Pread)]
struct CompressedSecondLevelPage {
    // Always 3 (use to distinguish from RegularSecondLevelPage).
    // kind: u32 = 3,

    /// The array of compressed u32 entries (offset relative to **start of this page**).
    ///
    /// Entries are a u32 that contains two packed values (from highest to lowest bits):
    /// * 8 bits: opcode index
    ///   * 0..global_opcodes_len => index into global palette
    ///   * global_opcodes_len..255 => index into local palette (subtract global_opcodes_len)
    /// * 24 bits: function address
    ///   * address is relative to this page's first_address!
    entries_offset: u16,
    entries_len: u16,

    /// The array of u32 local opcodes for this page (offset relative to **start of this page**).
    local_opcodes_offset: u16,
    local_opcodes_len: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Pread)]
struct RegularEntry {
  /// The address in the binary for this entry (absolute).
  instruction_address: u32,
  /// The opcode for this address.
  opcode: u32,
}

#[derive(Debug, Clone)]
#[repr(C)]
struct LsdaEntry {
    instruction_address: u32,
    lsda_address: u32,
}

#[derive(Debug, Clone)]
struct Opcode(u32);

#[derive(Debug, Clone)]
enum X86UnwindingMode {
    Old,
    RbpFrame,
    StackImmediate,
    StackIndirect,
    Dwarf,
}

/// Minimal set of CFI ops needed to express Compact Unwinding semantics:
#[derive(Debug, Clone)]
pub enum CfiOp {
    /// The value of `dest_reg` is *stored at* `src_reg + offset_from_src`.
    RegisterAt {
        /// Destination
        dest_reg: CfiRegister,
        /// Source
        src_reg: CfiRegister,
        /// Offset
        offset_from_src: i32,
    },
    /// The value of `dest_reg` *is* `src_reg + offset_from_src`.
    RegisterIs {
        /// Destination
        dest_reg: CfiRegister,
        /// Source
        src_reg: CfiRegister,
        /// Offset
        offset_from_src: i32,
    },
}

/// A register for a CfiOp, as used by Compact Unwinding.
///
/// You should just treat this opaquely and use its methods to make sense of it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CfiRegister {
    /// The CFA register (Canonical Frame Address) -- the frame pointer (e.g. rbp)
    Cfa,
    /// Any other register, restricted to those referenced by Compact Unwinding.
    Other(u8),
}

impl<'a> CompactUnwindInfoIter<'a> {
    pub fn new(section: SectionData<'a>, little_endian: bool, is_64: bool) -> error::Result<Self> {
        const UNWIND_SECTION_VERSION: u32 = 1;

        // TODO: do this properly
        let arch = if is_64 {
            Arch::X64
        } else {
            Arch::X86
        };

        let endian = if little_endian {
            Endian::Little
        } else {
            Endian::Big
        };

        let offset = &mut 0;

        // Grab all the fields from the header
        let version: u32 = section.gread_with(offset, endian)?;
        if version != UNWIND_SECTION_VERSION {
            return Err(Error::Malformed(format!("Unknown Compact Unwinding Info version {}", version)));
        }

        let root = section.gread_with(offset, endian)?;

        let iter = CompactUnwindInfoIter {
            arch,
            endian,
            section,
            root,

            first_idx: 0,
            second_idx: 0,
            page_of_next_entry: None,
            next_entry: None,
            done_page: true,
        };

        Ok(iter)
    }
    /// Gets the next entry in the iterator.
    pub fn next(&mut self) -> error::Result<Option<CompactUnwindInfoEntry>> {
        // Iteration is slightly more complex here because we want to be able to
        // report how many instructions an entry covers, and knowing this requires us
        // to parse the *next* entry's instruction_address value. Also, there's
        // a sentinel page at the end of the listing with a null second_level_page_offset
        // which requires some special handling.
        //
        // To handle this, we split iteration into two phases:
        //
        // * next_raw minimally parses the next entry so we can extract the opcode,
        //   while also ensuring page_of_next_entry is set to match it.
        //
        // * next uses next_raw to "peek" the instruction_address of the next entry,
        //   and then saves the result as `next_entry`, to avoid doing a bunch of
        //   repeated work.

        // If this is our first iteration next_entry will be empty, try to get it.
        if self.next_entry.is_none() {
            self.next_entry = self.next_raw()?;
        }

        if let Some(cur_entry) = self.next_entry.take() {
            // Copy the first and second page data, as it may get overwritten
            // by next_raw, then peek the next entry.
            let (first_page, second_page) = self.page_of_next_entry.clone().unwrap();
            self.next_entry = self.next_raw()?;
            if let Some(next_entry) = self.next_entry.as_ref() {
                let result = self.complete_entry(
                    &cur_entry,
                    next_entry.instruction_address,
                    &first_page,
                    &second_page,
                )?;
                Ok(Some(result))
            } else {
                // If there's no next_entry, then cur_entry is the sentinel, which
                // we shouldn't yield.
                Ok(None)
            }
        } else {
            // next_raw still yielded nothing, we're done.
            Ok(None)
        }
    }

    // Yields a minimally parsed version of the next entry, and sets
    // page_of_next_entry to the page matching it (so it can be further
    // parsed when needed.
    fn next_raw(&mut self) -> error::Result<Option<RawCompactUnwindInfoEntry>> {
        // First, load up the page for this value if needed
        if self.done_page {
            // Only advance the indices if we've already loaded up a page
            // (so it's not the first iteration) and we have pages left.
            if self.page_of_next_entry.is_some() && self.first_idx != self.root.pages_len {
                self.first_idx += 1;
                self.second_idx = 0;
            }
            if let Some(entry) = self.first_level_entry(self.first_idx)? {
                if entry.second_level_page_offset == 0 {
                    // sentinel page at the end of the list, create a dummy entry
                    // and advance past this page (don't reset done_page).
                    return Ok(Some(RawCompactUnwindInfoEntry {
                        instruction_address: entry.first_address,
                        opcode_or_index: OpcodeOrIndex::Opcode(0),
                    }));
                }
                let second_level_page = self.second_level_page(entry.second_level_page_offset)?;
                self.page_of_next_entry = Some((entry, second_level_page));
                self.done_page = false;
            } else {
                // Couldn't load a page, so we're at the end of our iteration.
                return Ok(None);
            }
        }

        // If we get here, we must have loaded a page
        let (first_level_entry, second_level_page) = self.page_of_next_entry.as_ref().unwrap();
        let entry =
            self.second_level_entry(&first_level_entry, &second_level_page, self.second_idx)?;

        // Advance to the next entry
        self.second_idx += 1;

        // If we reach the end of the page, setup for the next page
        if self.second_idx == second_level_page.len() {
            self.done_page = true;
        }

        Ok(Some(entry))
    }

    /// Gets the entry associated with a particular address.
    pub fn entry_for_address(&mut self, _address: u32) -> Option<CompactUnwindInfoEntry> {
        // TODO: this would be nice for an actual unwinding implementation, but
        // dumping all of the entries doesn't need this.
        unimplemented!()
    }

    fn first_level_entry(&self, idx: u32) -> error::Result<Option<FirstLevelPageEntry>> {
        if idx < self.root.pages_len {
            let idx_offset = mem::size_of::<FirstLevelPageEntry>() * idx as usize;
            let offset = self.root.pages_offset as usize + idx_offset;

            Ok(Some(self.section.pread_with(offset, self.endian)?))
        } else {
            Ok(None)
        }
    }

    fn second_level_page(&self, offset: u32) -> error::Result<SecondLevelPage> {
        const SECOND_LEVEL_REGULAR: u32 = 2;
        const SECOND_LEVEL_COMPRESSED: u32 = 3;

        let mut offset = offset as usize;

        let kind: u32 = self.section.gread_with(&mut offset, self.endian)?;
        if kind == SECOND_LEVEL_REGULAR {
            Ok(SecondLevelPage::Regular(self.section.gread_with(&mut offset, self.endian)?))
        } else if kind == SECOND_LEVEL_COMPRESSED {
            Ok(SecondLevelPage::Compressed(self.section.gread_with(&mut offset, self.endian)?))
        } else {
            Err(Error::Malformed(format!("Unknown second-level page kind: {}", kind)))
        }
    }

    fn second_level_entry(
        &self,
        first_level_entry: &FirstLevelPageEntry,
        second_level_page: &SecondLevelPage,
        second_level_idx: u32,
    ) -> error::Result<RawCompactUnwindInfoEntry> {
        match *second_level_page {
            SecondLevelPage::Compressed(ref page) => {
                let offset = first_level_entry.second_level_page_offset as usize
                        + page.entries_offset as usize
                        + second_level_idx as usize * 4;
                let compressed_entry: u32 = self.section.pread_with(offset, self.endian)?;

                let instruction_address =
                    (compressed_entry & 0x00FFFFFF) + first_level_entry.first_address;
                let opcode_idx = (compressed_entry >> 24) & 0xFF;
                Ok(RawCompactUnwindInfoEntry {
                    instruction_address,
                    opcode_or_index: OpcodeOrIndex::Index(opcode_idx),
                })
            }
            SecondLevelPage::Regular(ref page) => {
                let offset = first_level_entry.second_level_page_offset as usize
                        + page.entries_offset as usize
                        + second_level_idx as usize * 8;

                let entry: RegularEntry = self.section.pread_with(offset, self.endian)?;

                Ok(RawCompactUnwindInfoEntry {
                    instruction_address: entry.instruction_address,
                    opcode_or_index: OpcodeOrIndex::Opcode(entry.opcode),
                })
            }
        }
    }

    fn complete_entry(
        &self,
        entry: &RawCompactUnwindInfoEntry,
        next_entry_instruction_address: u32,
        first_level_entry: &FirstLevelPageEntry,
        second_level_page: &SecondLevelPage,
    ) -> error::Result<CompactUnwindInfoEntry> {
        let opcode = match entry.opcode_or_index {
            OpcodeOrIndex::Opcode(opcode) => opcode,
            OpcodeOrIndex::Index(opcode_idx) => {
                if let SecondLevelPage::Compressed(ref page) = second_level_page {
                    if opcode_idx < self.root.global_opcodes_len {
                        self.global_opcode(opcode_idx)?
                    } else {
                        let opcode_idx = opcode_idx - self.root.global_opcodes_len;
                        if opcode_idx >= page.local_opcodes_len as u32 {
                            return Err(Error::Malformed(format!("Local opcode index too large ({} >= {})", opcode_idx, page.local_opcodes_len)))
                        }
                        let offset = first_level_entry.second_level_page_offset as usize
                                + page.local_opcodes_offset as usize
                                + opcode_idx as usize * 4;
                        let opcode: u32 = self.section.pread_with(offset, self.endian)?;
                        opcode
                    }
                } else {
                    unreachable!()
                }
            }
        };
        let opcode = Opcode(opcode);

        Ok(CompactUnwindInfoEntry {
            instruction_address: entry.instruction_address,
            len: next_entry_instruction_address - entry.instruction_address,
            opcode,
        })
    }

    fn global_opcode(&self, opcode_idx: u32) -> error::Result<u32> {
        if opcode_idx >= self.root.global_opcodes_len {
            return Err(Error::Malformed(format!("Global opcode index too large ({} >= {})", opcode_idx, self.root.global_opcodes_len)))
        }
        let offset = self.root.global_opcodes_offset as usize + opcode_idx as usize * 4;
        let opcode: u32 = self.section.pread_with(offset, self.endian)?;
        Ok(opcode)
    }

    fn personality(&self, personality_idx: u32) -> error::Result<u32> {
        if personality_idx >= self.root.personalities_len {
            return Err(Error::Malformed(format!("Personality index too large ({} >= {})", personality_idx, self.root.personalities_len)))
        }
        let offset = self.root.personalities_offset as usize + personality_idx as usize * 4;
        let personality: u32 = self.section.pread_with(offset, self.endian)?;
        Ok(personality)
    }

    /// Dumps similar output to `llvm-objdump --unwind-info`, for debugging.
    pub fn dump(&self) -> error::Result<()> {
        println!("Contents of __unwind_info section:");
        println!("  Version:                                   0x1");
        println!(
            "  Common encodings array section offset:     0x{:x}",
            self.root.global_opcodes_offset
        );
        println!(
            "  Number of common encodings in array:       0x{:x}",
            self.root.global_opcodes_len
        );
        println!(
            "  Personality function array section offset: 0x{:x}",
            self.root.personalities_offset
        );
        println!(
            "  Number of personality functions in array:  0x{:x}",
            self.root.personalities_len
        );
        println!(
            "  Index array section offset:                0x{:x}",
            self.root.pages_offset
        );
        println!(
            "  Number of indices in array:                0x{:x}",
            self.root.pages_len
        );

        println!("  Common encodings: (count = {})", self.root.global_opcodes_len);
        for i in 0..self.root.global_opcodes_len {
            let opcode = self.global_opcode(i)?;
            println!("    encoding[{}]: 0x{:08x}", i, opcode);
        }

        println!(
            "  Personality functions: (count = {})",
            self.root.personalities_len
        );
        for i in 0..self.root.personalities_len {
            let personality = self.personality(i)?;
            println!("    personality[{}]: 0x{:08x}", i, personality);
        }

        println!("  Top level indices: (count = {})", self.root.pages_len);
        for i in 0..self.root.pages_len {
            let entry = self.first_level_entry(i)?.unwrap();
            println!("    [{}]: function offset=0x{:08x}, 2nd level page offset=0x{:08x}, LSDA offset=0x{:08x}",
                    i,
                    entry.first_address,
                    entry.second_level_page_offset,
                    entry.lsda_index_offset);
        }

        // TODO: print LSDA info
        println!("  LSDA descriptors:");
        println!("  Second level indices:");

        let mut iter = (*self).clone();
        while let Some(raw_entry) = iter.next_raw()? {
            let (first, second) = iter.page_of_next_entry.clone().unwrap();
            // Always observing the index after the step, so subtract 1
            let second_idx = iter.second_idx - 1;

            // If this is the first entry of this page, dump the page
            if second_idx == 0 {
                println!("    Second level index[{}]: offset in section=0x{:08x}, base function=0x{:08x}",
                iter.first_idx,
                first.second_level_page_offset,
                first.first_address);
            }

            // Dump the entry

            // Feed in own instruction_address as a dummy value (we don't need it for this format)
            let entry =
                iter.complete_entry(&raw_entry, raw_entry.instruction_address, &first, &second)?;
            if let OpcodeOrIndex::Index(opcode_idx) = raw_entry.opcode_or_index {
                println!(
                    "      [{}]: function offset=0x{:08x}, encoding[{}]=0x{:08x}",
                    second_idx, entry.instruction_address, opcode_idx, entry.opcode.0
                );
            } else {
                println!(
                    "      [{}]: function offset=0x{:08x}, encoding=0x{:08x}",
                    second_idx, entry.instruction_address, entry.opcode.0
                );
            }
        }

        Ok(())
    }
}

impl SecondLevelPage {
    fn len(&self) -> u32 {
        match *self {
            SecondLevelPage::Regular(ref page) => page.entries_len as u32,
            SecondLevelPage::Compressed(ref page) => page.entries_len as u32,
        }
    }
}

impl CompactUnwindInfoEntry {
    /// Gets cfi instructions associated with this entry.
    pub fn cfi_instructions(
        &self,
        iter: &CompactUnwindInfoIter,
    ) -> Option<impl Iterator<Item = CfiOp>> {
        self.opcode.cfi_instructions(iter)
    }
}

// Arch-generic stuff
impl Opcode {
    fn cfi_instructions(
        &self,
        iter: &CompactUnwindInfoIter,
    ) -> Option<impl Iterator<Item = CfiOp>> {
        match iter.arch {
            Arch::X86 | Arch::X64  => {
                self.x86_cfi_instructions(iter)
            }
            Arch::Arm64 => {
                self.arm64_cfi_instructions(iter)
            }
            _ => None,
        }
    }

    fn pointer_size(&self, iter: &CompactUnwindInfoIter) -> u32 {
        match iter.arch {
            Arch::X86 => 4,
            Arch::X64 => 8,
            Arch::Arm64 => 8,
            _ => unimplemented!(),
        }
    }

    /*
    // potentially needed for future work:

    fn is_start(&self) -> bool {
        let offset = 32 - 1;
        (self.0 & (1 << offset)) != 0
    }
    fn has_lsda(&self) -> bool{
        let offset = 32 - 2;
        (self.0 & (1 << offset)) != 0
    }
    fn personality_index(&self) -> u32 {
        let offset = 32 - 4;
        (self.0 >> offset) & 0b11
    }
    */
}

// x86/x64 implementation
impl Opcode {
    fn x86_cfi_instructions(
        &self,
        iter: &CompactUnwindInfoIter,
    ) -> Option<std::vec::IntoIter<CfiOp>> {
        let pointer_size = self.pointer_size(iter) as i32;
        // TODO: don't allocate for this (use ArrayVec..?)
        match self.x86_mode() {
            Some(X86UnwindingMode::Old) => None,
            Some(X86UnwindingMode::RbpFrame) => {
                // This function has the standard function prelude and rbp
                // has been preserved. Additionally, any callee-saved registers
                // that haven't been preserved (x86_rbp_registers) are saved on
                // the stack at x86_rbp_stack_offset.
                let mut ops = vec![
                    CfiOp::RegisterIs {
                        dest_reg: CfiRegister::Cfa,
                        src_reg: CfiRegister::frame_pointer(),
                        offset_from_src: 2 * pointer_size,
                    },
                    CfiOp::RegisterAt {
                        dest_reg: CfiRegister::frame_pointer(),
                        src_reg: CfiRegister::Cfa,
                        offset_from_src: -2 * pointer_size,
                    },
                    CfiOp::RegisterAt {
                        dest_reg: CfiRegister::instruction_pointer(),
                        src_reg: CfiRegister::Cfa,
                        offset_from_src: -1 * pointer_size,
                    },
                ];

                // These offsets are relative to the frame pointer, but
                // cfi prefers things to be relative to the cfa, so apply
                // the same offset here too.
                let offset = self.x86_rbp_stack_offset() as i32 + 2;
                // Offset advances even if there's no register here
                for (i, reg) in self.x86_rbp_registers().iter().enumerate() {
                    if let Some(reg) = *reg {
                        ops.push(CfiOp::RegisterAt {
                            dest_reg: reg,
                            src_reg: CfiRegister::Cfa,
                            offset_from_src: (offset - i as i32) * pointer_size,
                        });
                    }
                }
                Some(ops.into_iter())
            }
            Some(X86UnwindingMode::StackImmediate) => {
                // This function doesn't have the standard rbp-based prelude,
                // but we know how large its stack frame is (x86_frameless_stack_size),
                // and any callee-saved registers that haven't been preserved are
                // saved *immediately* after the location at rip.

                let mut ops = vec![];

                let stack_size = self.x86_frameless_stack_size();
                ops.push(CfiOp::RegisterIs {
                    dest_reg: CfiRegister::Cfa,
                    src_reg: CfiRegister::stack_pointer(),
                    offset_from_src: stack_size as i32 * pointer_size,
                });
                ops.push(CfiOp::RegisterAt {
                    dest_reg: CfiRegister::instruction_pointer(),
                    src_reg: CfiRegister::Cfa,
                    offset_from_src: -1 * pointer_size,
                });

                let mut offset = 2;
                // offset only advances if there's a register here.
                // also note registers are in reverse order.
                for reg in self.x86_frameless_registers().iter().rev() {
                    if let Some(reg) = *reg {
                        ops.push(CfiOp::RegisterAt {
                            dest_reg: reg,
                            src_reg: CfiRegister::Cfa,
                            offset_from_src: -offset * pointer_size,
                        });
                        offset += 1;
                    }
                }
                Some(ops.into_iter())
            }
            Some(X86UnwindingMode::StackIndirect) => {
                // TODO: implement this? Perhaps there is no reasonable implementation
                // since this involves parsing a value out of a machine instruction
                // in the binary? Or can we just do that work here and it just
                // becomes a constant in the CFI output?
                //
                // Either way it's not urgent, since this mode is only needed for
                // stack frames that are bigger than ~2KB.
                None
            }
            Some(X86UnwindingMode::Dwarf) => None,
            None => None,
        }
    }

    fn x86_mode(&self) -> Option<X86UnwindingMode> {
        const X86_MODE_MASK: u32 = 0x0F00_0000;
        const X86_MODE_OLD: u32 = 0x0000_0000;
        const X86_MODE_RBP_FRAME: u32 = 0x0100_0000;
        const X86_MODE_STACK_IMMD: u32 = 0x0200_0000;
        const X86_MODE_STACK_IND: u32 = 0x0300_0000;
        const X86_MODE_DWARF: u32 = 0x0400_0000;

        let masked = self.0 & X86_MODE_MASK;

        match masked {
            X86_MODE_OLD => Some(X86UnwindingMode::Old),
            X86_MODE_RBP_FRAME => Some(X86UnwindingMode::RbpFrame),
            X86_MODE_STACK_IMMD => Some(X86UnwindingMode::StackImmediate),
            X86_MODE_STACK_IND => Some(X86UnwindingMode::StackIndirect),
            X86_MODE_DWARF => Some(X86UnwindingMode::Dwarf),
            _ => None,
        }
    }

    fn x86_rbp_registers(&self) -> [Option<CfiRegister>; 5] {
        let mask = 0b111;
        let offset1 = 32 - 8 - 3;
        let offset2 = offset1 - 3;
        let offset3 = offset2 - 3;
        let offset4 = offset3 - 3;
        let offset5 = offset4 - 3;
        [
            CfiRegister::from_encoded((self.0 >> offset1) & mask),
            CfiRegister::from_encoded((self.0 >> offset2) & mask),
            CfiRegister::from_encoded((self.0 >> offset3) & mask),
            CfiRegister::from_encoded((self.0 >> offset4) & mask),
            CfiRegister::from_encoded((self.0 >> offset5) & mask),
        ]
    }

    fn x86_rbp_stack_offset(&self) -> u32 {
        self.0 & 0b1111_1111
    }

    fn x86_frameless_stack_size(&self) -> u32 {
        let offset = 32 - 8 - 8;
        (self.0 >> offset) & 0b1111_1111
    }

    fn x86_frameless_register_count(&self) -> u32 {
        let offset = 32 - 8 - 8 - 3 - 3;
        (self.0 >> offset) & 0b111
    }

    fn x86_frameless_registers(&self) -> [Option<CfiRegister>; 6] {
        let mut permutation = self.0 & 0b11_1111_1111;
        let mut permunreg = [0; 6];
        let register_count = self.x86_frameless_register_count();

        // I honestly haven't looked into what the heck this is doing, I
        // just copied this implementation from llvm since it honestly doesn't
        // matter much. Magically unpack 6 values from 10 bits!
        match register_count {
            6 => {
                permunreg[0] = permutation / 120; // 120 == 5!
                permutation -= permunreg[0] * 120;
                permunreg[1] = permutation / 24; // 24 == 4!
                permutation -= permunreg[1] * 24;
                permunreg[2] = permutation / 6; // 6 == 3!
                permutation -= permunreg[2] * 6;
                permunreg[3] = permutation / 2; // 2 == 2!
                permutation -= permunreg[3] * 2;
                permunreg[4] = permutation; // 1 == 1!
                permunreg[5] = 0;
            }
            5 => {
                permunreg[0] = permutation / 120;
                permutation -= permunreg[0] * 120;
                permunreg[1] = permutation / 24;
                permutation -= permunreg[1] * 24;
                permunreg[2] = permutation / 6;
                permutation -= permunreg[2] * 6;
                permunreg[3] = permutation / 2;
                permutation -= permunreg[3] * 2;
                permunreg[4] = permutation;
            }
            4 => {
                permunreg[0] = permutation / 60;
                permutation -= permunreg[0] * 60;
                permunreg[1] = permutation / 12;
                permutation -= permunreg[1] * 12;
                permunreg[2] = permutation / 3;
                permutation -= permunreg[2] * 3;
                permunreg[3] = permutation;
            }
            3 => {
                permunreg[0] = permutation / 20;
                permutation -= permunreg[0] * 20;
                permunreg[1] = permutation / 4;
                permutation -= permunreg[1] * 4;
                permunreg[2] = permutation;
            }
            2 => {
                permunreg[0] = permutation / 5;
                permutation -= permunreg[0] * 5;
                permunreg[1] = permutation;
            }
            1 => {
                permunreg[0] = permutation;
            }
            _ => {
                // Do nothing
            }
        }

        let mut registers = [0u32; 6];
        let mut used = [false; 7];
        for i in 0..register_count {
            let mut renum = 0;
            for j in 1u32..7 {
                if !used[j as usize] {
                    if renum == permunreg[i as usize] {
                        registers[i as usize] = j;
                        used[j as usize] = true;
                        break;
                    }
                    renum += 1;
                }
            }
        }
        [
            CfiRegister::from_encoded(registers[0]),
            CfiRegister::from_encoded(registers[1]),
            CfiRegister::from_encoded(registers[2]),
            CfiRegister::from_encoded(registers[3]),
            CfiRegister::from_encoded(registers[4]),
            CfiRegister::from_encoded(registers[5]),
        ]
    }
    /*
    // potentially needed for future work:

    fn x86_frameless_stack_adjust(&self) -> u32 {
        let offset = 32 - 8 - 8 - 3;
        (self.0 >> offset) & 0b111
    }
    fn x86_dwarf_fde(&self) -> u32 {
        self.0 & 0x00FF_FFFF
    }
    */
}

// ARM64 implementation
impl Opcode {
    fn arm64_cfi_instructions(
        &self,
        _iter: &CompactUnwindInfoIter,
    ) -> Option<std::vec::IntoIter<CfiOp>> {
        // TODO: implement ARM64 decoding
        None
    }
}

impl CfiRegister {
    fn from_encoded(val: u32) -> Option<Self> {
        if 1 <= val && val <= 6 {
            Some(CfiRegister::Other(val as u8))
        } else {
            None
        }
    }

    /// Whether this register is the cfa register.
    pub fn is_cfa(&self) -> bool {
        matches!(*self, CfiRegister::Cfa)
    }

    /// The name of this register that cfi wants.
    pub fn name(&self, iter: &CompactUnwindInfoIter) -> Option<&'static str> {
        match self {
            CfiRegister::Cfa => Some("cfa"),
            CfiRegister::Other(other) => name_of_other_reg(*other, iter),
        }
    }

    /// Gets the register for the frame pointer (e.g. rbp).
    pub fn frame_pointer() -> Self {
        CfiRegister::Other(6)
    }

    /// Gets the register for the instruction pointer (e.g. rip).
    pub fn instruction_pointer() -> Self {
        CfiRegister::Other(254)
    }

    /// Gets the register for the stack pointer (e.g. rsp).
    pub fn stack_pointer() -> Self {
        CfiRegister::Other(255)
    }
}

fn name_of_other_reg(reg: u8, iter: &CompactUnwindInfoIter) -> Option<&'static str> {
    match iter.arch {
        Arch::X86 => match reg {
            0 => None,
            1 => Some("ebx"),
            2 => Some("ecx"),
            3 => Some("edx"),
            4 => Some("edi"),
            5 => Some("esi"),
            6 => Some("ebp"),
            // Not part of the compact format, but needed to describe opcode behaviours
            254 => Some("eip"),
            255 => Some("esp"),

            _ => None,
        },
        Arch::X64 => match reg {
            0 => None,
            1 => Some("rbx"),
            2 => Some("r12"),
            3 => Some("r13"),
            4 => Some("r14"),
            5 => Some("r15"),
            6 => Some("rbp"),
            // Not part of the compact format, but needed to describe opcode behaviours
            254 => Some("rip"),
            255 => Some("rsp"),
            _ => None,
        },
        Arch::Arm64 => {
            unimplemented!();
            // Leaving these here to help whoever decides to implement ARM64 support
            /*
            match reg {
                0x00000001 => Some("x19/x20"),
                0x00000002 => Some("x21/x22"),
                0x00000004 => Some("x23/x24"),
                0x00000008 => Some("x25/x26"),
                0x00000010 => Some("x27/x28"),
                0x00000100 => Some("d8/d9"),
                0x00000200 => Some("d10/d11"),
                0x00000400 => Some("d12/d13"),
                0x00000800 => Some("d14/d15"),
                _ => None
            }
            */
        }
        _ => None,
    }
}
