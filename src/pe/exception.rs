//! Exception handling and stack unwinding for x64.
//!
//! Exception information is exposed via the [`ExceptionData`] structure. If present in a PE file,
//! it contains a list of [`RuntimeFunction`] entries that can be used to get [`UnwindInfo`] for a
//! particular code location.
//!
//! Unwind information contains a list of unwind codes which specify the operations that are
//! necessary to restore registers (including the stack pointer RSP) when unwinding out of a
//! function.
//!
//! Depending on where the instruction pointer lies, there are three strategies to unwind:
//!
//!  1. If the RIP is within an epilog, then control is leaving the function, there can be no
//!     exception handler associated with this exception for this function, and the effects of the
//!     epilog must be continued to compute the context of the caller function. To determine if the
//!     RIP is within an epilog, the code stream from RIP on is examined. If that code stream can be
//!     matched to the trailing portion of a legitimate epilog, then it's in an epilog, and the
//!     remaining portion of the epilog is simulated, with the context record updated as each
//!     instruction is processed. After this, step 1 is repeated.
//!
//!  2. Case b) If the RIP lies within the prologue, then control has not entered the function,
//!     there can be no exception handler associated with this exception for this function, and the
//!     effects of the prolog must be undone to compute the context of the caller function. The RIP
//!     is within the prolog if the distance from the function start to the RIP is less than or
//!     equal to the prolog size encoded in the unwind info. The effects of the prolog are unwound
//!     by scanning forward through the unwind codes array for the first entry with an offset less
//!     than or equal to the offset of the RIP from the function start, then undoing the effect of
//!     all remaining items in the unwind code array. Step 1 is then repeated.
//!
//!  3. If the RIP is not within a prolog or epilog and the function has an exception handler, then
//!     the language-specific handler is called. The handler scans its data and calls filter
//!     functions as appropriate. The language-specific handler can return that the exception was
//!     handled or that the search is to be continued. It can also initiate an unwind directly.
//!
//! For more information, see [x64 exception handling].
//!
//! [`ExceptionData`]: struct.ExceptionData.html
//! [`RuntimeFunction`]: struct.RuntimeFunction.html
//! [`UnwindInfo`]: struct.UnwindInfo.html
//! [x64 exception handling]: https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=vs-2017

use core::cmp::Ordering;
use core::fmt;
use core::iter::FusedIterator;

use scroll::ctx::TryFromCtx;
use scroll::{self, Pread, Pwrite, SizeWith};

use crate::error;

use crate::pe::data_directories;
use crate::pe::options;
use crate::pe::section_table;
use crate::pe::utils;

/// **N**o handlers.
#[allow(unused)]
const UNW_FLAG_NHANDLER: u8 = 0x00;
/// The function has an exception handler that should be called when looking for functions that need
/// to examine exceptions.
const UNW_FLAG_EHANDLER: u8 = 0x01;
/// The function has a termination handler that should be called when unwinding an exception.
const UNW_FLAG_UHANDLER: u8 = 0x02;
/// This unwind info structure is not the primary one for the procedure. Instead, the chained unwind
/// info entry is the contents of a previous `RUNTIME_FUNCTION` entry. If this flag is set, then the
/// `UNW_FLAG_EHANDLER` and `UNW_FLAG_UHANDLER` flags must be cleared. Also, the frame register and
/// fixed-stack allocation fields must have the same values as in the primary unwind info.
const UNW_FLAG_CHAININFO: u8 = 0x04;

/// info == register number
const UWOP_PUSH_NONVOL: u8 = 0;
/// no info, alloc size in next 2 slots
const UWOP_ALLOC_LARGE: u8 = 1;
/// info == size of allocation / 8 - 1
const UWOP_ALLOC_SMALL: u8 = 2;
/// no info, FP = RSP + UNWIND_INFO.FPRegOffset*16
const UWOP_SET_FPREG: u8 = 3;
/// info == register number, offset in next slot
const UWOP_SAVE_NONVOL: u8 = 4;
/// info == register number, offset in next 2 slots
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
/// changes the structure of unwind codes to `struct Epilogue`.
/// (was UWOP_SAVE_XMM in version 1, but deprecated and removed)
const UWOP_EPILOG: u8 = 6;
/// reserved
/// (was UWOP_SAVE_XMM_FAR in version 1, but deprecated and removed)
const UWOP_SPARE_CODE: u8 = 7;
/// info == XMM reg number, offset in next slot
const UWOP_SAVE_XMM128: u8 = 8;
/// info == XMM reg number, offset in next 2 slots
const UWOP_SAVE_XMM128_FAR: u8 = 9;
/// info == 0: no error-code, 1: error-code
const UWOP_PUSH_MACHFRAME: u8 = 10;

/// Size of `RuntimeFunction` entries.
const RUNTIME_FUNCTION_SIZE: usize = 12;
/// Size of unwind code slots. Codes take 1 - 3 slots.
const UNWIND_CODE_SIZE: usize = 2;

/// Represents a single entry in a Windows PE exception handling scope table `C_SCOPE_TABLE_ENTRY`.
///
/// Each entry defines a protected range of code and its associated exception handler.
/// These entries are typically found in the scope table associated with `UNWIND_INFO`
/// structures in Windows x64 exception handling.
#[derive(Debug, Copy, Clone, Default, PartialEq, Hash, Pread, Pwrite, SizeWith)]
#[repr(C)]
pub struct ScopeTableEntry {
    /// The starting RVA (relative virtual address) of the protected code region.
    ///
    /// This marks the beginning of a `try` block.
    pub begin: u32,

    /// The ending RVA (exclusive) of the protected code region.
    ///
    /// This marks the end of the `try` block.
    pub end: u32,

    /// The RVA of the exception handler function.
    ///
    /// e.g., be invoked when an exception occurs in the associated code range.
    pub handler: u32,

    /// The RVA of the continuation target after the handler is executed.
    ///
    /// This is used for control transfer (e.g., continuation blocks, to resume execution after `finally`).
    pub target: u32,
}

/// Iterator over [ScopeTableEntry] entries in `C_SCOPE_TABLE`.
#[derive(Debug)]
pub struct ScopeTableIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl Iterator for ScopeTableIterator<'_> {
    type Item = ScopeTableEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        // It is guaranteed that .expect here is really a unreachable.
        // See: that we do `num_entries * core::mem::size_of::<ScopeTableEntry>() as u32;`
        Some(
            self.data
                .gread_with(&mut self.offset, scroll::LE)
                .expect("Scope table is not aligned"),
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.data.len() / core::mem::size_of::<ScopeTableEntry>();
        (len, Some(len))
    }
}

impl FusedIterator for ScopeTableIterator<'_> {}
impl ExactSizeIterator for ScopeTableIterator<'_> {}

/// An unwind entry for a range of a function.
///
/// Unwind information for this function can be loaded with [`ExceptionData::get_unwind_info`].
///
/// [`ExceptionData::get_unwind_info`]: struct.ExceptionData.html#method.get_unwind_info
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Default, Pread, Pwrite)]
pub struct RuntimeFunction {
    /// Function start address.
    pub begin_address: u32,
    /// Function end address.
    pub end_address: u32,
    /// Unwind info address.
    pub unwind_info_address: u32,
}

impl fmt::Debug for RuntimeFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RuntimeFunction")
            .field("begin_address", &format_args!("{:#x}", self.begin_address))
            .field("end_address", &format_args!("{:#x}", self.end_address))
            .field(
                "unwind_info_address",
                &format_args!("{:#x}", self.unwind_info_address),
            )
            .finish()
    }
}

/// Iterator over runtime function entries in [`ExceptionData`](struct.ExceptionData.html).
#[derive(Debug)]
pub struct RuntimeFunctionIterator<'a> {
    data: &'a [u8],
}

impl Iterator for RuntimeFunctionIterator<'_> {
    type Item = error::Result<RuntimeFunction>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        Some(match self.data.pread_with(0, scroll::LE) {
            Ok(func) => {
                self.data = &self.data[RUNTIME_FUNCTION_SIZE..];
                Ok(func)
            }
            Err(error) => {
                self.data = &[];
                Err(error.into())
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.data.len() / RUNTIME_FUNCTION_SIZE;
        (len, Some(len))
    }
}

impl FusedIterator for RuntimeFunctionIterator<'_> {}
impl ExactSizeIterator for RuntimeFunctionIterator<'_> {}

/// An x64 register used during unwinding.
///
///  - `0` - `15`: General purpose registers
///  - `17` - `32`: XMM registers
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Register(pub u8);

impl Register {
    fn xmm(number: u8) -> Self {
        Register(number + 17)
    }

    /// Returns the x64 register name.
    pub fn name(self) -> &'static str {
        match self.0 {
            0 => "$rax",
            1 => "$rcx",
            2 => "$rdx",
            3 => "$rbx",
            4 => "$rsp",
            5 => "$rbp",
            6 => "$rsi",
            7 => "$rdi",
            8 => "$r8",
            9 => "$r9",
            10 => "$r10",
            11 => "$r11",
            12 => "$r12",
            13 => "$r13",
            14 => "$r14",
            15 => "$r15",
            16 => "$rip",
            17 => "$xmm0",
            18 => "$xmm1",
            19 => "$xmm2",
            20 => "$xmm3",
            21 => "$xmm4",
            22 => "$xmm5",
            23 => "$xmm6",
            24 => "$xmm7",
            25 => "$xmm8",
            26 => "$xmm9",
            27 => "$xmm10",
            28 => "$xmm11",
            29 => "$xmm12",
            30 => "$xmm13",
            31 => "$xmm14",
            32 => "$xmm15",
            _ => "",
        }
    }
}

/// An unsigned offset to a value in the local stack frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackFrameOffset {
    /// Offset from the current RSP, that is, the lowest address of the fixed stack allocation.
    ///
    /// To restore this register, read the value at the given offset from the RSP.
    RSP(u32),

    /// Offset from the value of the frame pointer register.
    ///
    /// To restore this register, read the value at the given offset from the FP register, reduced
    /// by the `frame_register_offset` value specified in the `UnwindInfo` structure. By definition,
    /// the frame pointer register is any register other than RAX (`0`).
    FP(u32),
}

impl StackFrameOffset {
    fn with_ctx(offset: u32, ctx: UnwindOpContext) -> Self {
        match ctx.frame_register {
            Register(0) => StackFrameOffset::RSP(offset),
            Register(_) => StackFrameOffset::FP(offset),
        }
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An unwind operation corresponding to code in the function prolog.
///
/// Unwind operations can be used to reverse the effects of the function prolog and restore register
/// values of parent stack frames that have been saved to the stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnwindOperation {
    /// Push a nonvolatile integer register, decrementing `RSP` by 8.
    PushNonVolatile(Register),

    /// Allocate a fixed-size area on the stack.
    Alloc(u32),

    /// Establish the frame pointer register by setting the register to some offset of the current
    /// RSP. The use of an offset permits establishing a frame pointer that points to the middle of
    /// the fixed stack allocation, helping code density by allowing more accesses to use short
    /// instruction forms.
    SetFPRegister,

    /// Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is
    /// primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a
    /// position that was previously allocated.
    SaveNonVolatile(Register, StackFrameOffset),

    /// Save the lower 64 bits of a nonvolatile XMM register on the stack.
    SaveXMM(Register, StackFrameOffset),

    /// Describes the function epilog location and size (Version 2).
    ///
    /// [UWOP_EPILOG] entries work together to describe where epilogues are located in the function,
    /// but not what operations they perform. The actual operations performed during epilogue
    /// execution are the reverse of the prolog operations.
    ///
    /// These entries always appear at the beginning of the [UnwindCode] array, with a minimum of
    /// two entries required for alignment purposes, even when only one epilogue exists. The first
    /// [UWOP_EPILOG] entry is special as it contains the size of the epilogue in its `offset_low_or_size`
    /// field. If bit `0` of its `offset_high_or_flags` field is set, this first entry also describes
    /// an epilogue located at the function's end, with `offset_low_or_size` serving dual purpose as
    /// both size and offset. When bit `0` is not set, the first entry contains only the size, and
    /// subsequent [UWOP_EPILOG] entries provide the epilogue locations.
    ///
    /// Each subsequent [UWOP_EPILOG] entry describes an additional epilogue location using a 12-bit
    /// offset from the function's end address. The offset is formed by combining `offset_low_or_size`
    /// (lower 8 bits) with the lower 4 bits of `offset_high_or_flags` (upper 4 bits). The epilogue's
    /// starting address is calculated by subtracting this offset from the function's `EndAddress`.
    Epilog {
        /// For the first [UWOP_EPILOG] entry:
        /// * Size of the epilogue in bytes
        /// * If `offset_high_or_flags` bit 0 is set, also serves as offset
        ///
        /// For subsequent entries:
        /// * Lower 8 bits of the offset from function end
        offset_low_or_size: u8,

        /// For the first [UWOP_EPILOG] entry:
        /// * Bit 0: If set, epilogue is at function end and `offset_low_or_size`
        ///   is also the offset
        /// * Bits 1-3: Reserved/unused
        ///
        /// For subsequent entries:
        /// * Upper 4 bits of the offset from function end (bits 0-3)
        ///
        /// The complete offset is computed as:
        /// `EndAddress` - (`offset_high_or_flags` << 8 | `offset_low_or_size`)
        offset_high_or_flags: u8,
    },

    /// Save all 128 bits of a nonvolatile XMM register on the stack.
    SaveXMM128(Register, StackFrameOffset),

    /// Push a machine frame. This is used to record the effect of a hardware interrupt or
    /// exception. Depending on the error flag, this frame has two different layouts.
    ///
    /// This unwind code always appears in a dummy prolog, which is never actually executed but
    /// instead appears before the real entry point of an interrupt routine, and exists only to
    /// provide a place to simulate the push of a machine frame. This operation records that
    /// simulation, which indicates the machine has conceptually done this:
    ///
    ///  1. Pop RIP return address from top of stack into `temp`
    ///  2. `$ss`, Push old `$rsp`, `$rflags`, `$cs`, `temp`
    ///  3. If error flag is `true`, push the error code
    ///
    /// Without an error code, RSP was incremented by `40` and the following was frame pushed:
    ///
    /// Offset   | Value
    /// ---------|--------
    /// RSP + 32 | `$ss`
    /// RSP + 24 | old `$rsp`
    /// RSP + 16 | `$rflags`
    /// RSP +  8 | `$cs`
    /// RSP +  0 | `$rip`
    ///
    /// With an error code, RSP was incremented by `48` and the following was frame pushed:
    ///
    /// Offset   | Value
    /// ---------|--------
    /// RSP + 40 | `$ss`
    /// RSP + 32 | old `$rsp`
    /// RSP + 24 | `$rflags`
    /// RSP + 16 | `$cs`
    /// RSP +  8 | `$rip`
    /// RSP +  0 | error code
    PushMachineFrame(bool),

    /// A reserved operation without effect.
    Noop,
}

/// Context used to parse unwind operation.
#[derive(Clone, Copy, Debug, PartialEq)]
struct UnwindOpContext {
    /// Version of the unwind info.
    version: u8,

    /// The nonvolatile register used as the frame pointer of this function.
    ///
    /// If this register is non-zero, all stack frame offsets used in unwind operations are of type
    /// `StackFrameOffset::FP`. When loading these offsets, they have to be based off the value of
    /// this frame register instead of the conventional RSP. This allows the RSP to be modified.
    frame_register: Register,
}

/// An unwind operation that is executed at a particular place in the function prolog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnwindCode {
    /// Offset of the corresponding instruction in the function prolog.
    ///
    /// To be precise, this is the offset from the beginning of the prolog of the end of the
    /// instruction that performs this operation, plus 1 (that is, the offset of the start of the
    /// next instruction).
    ///
    /// Unwind codes are ordered by this offset in reverse order, suitable for unwinding.
    pub code_offset: u8,

    /// The operation that was performed by the code in the prolog.
    pub operation: UnwindOperation,
}

impl<'a> TryFromCtx<'a, UnwindOpContext> for UnwindCode {
    type Error = error::Error;
    #[inline]
    fn try_from_ctx(bytes: &'a [u8], ctx: UnwindOpContext) -> Result<(Self, usize), Self::Error> {
        let mut read = 0;
        let code_offset = bytes.gread_with::<u8>(&mut read, scroll::LE)?;
        let operation = bytes.gread_with::<u8>(&mut read, scroll::LE)?;

        let operation_code = operation & 0xf;
        let operation_info = operation >> 4;

        let operation = match operation_code {
            self::UWOP_PUSH_NONVOL => {
                let register = Register(operation_info);
                UnwindOperation::PushNonVolatile(register)
            }
            self::UWOP_ALLOC_LARGE => {
                let offset = match operation_info {
                    0 => u32::from(bytes.gread_with::<u16>(&mut read, scroll::LE)?) * 8,
                    1 => bytes.gread_with::<u32>(&mut read, scroll::LE)?,
                    i => {
                        let msg = format!("invalid op info ({}) for UWOP_ALLOC_LARGE", i);
                        return Err(error::Error::Malformed(msg));
                    }
                };
                UnwindOperation::Alloc(offset)
            }
            self::UWOP_ALLOC_SMALL => {
                let offset = u32::from(operation_info) * 8 + 8;
                UnwindOperation::Alloc(offset)
            }
            self::UWOP_SET_FPREG => UnwindOperation::SetFPRegister,
            self::UWOP_SAVE_NONVOL => {
                let register = Register(operation_info);
                let offset = u32::from(bytes.gread_with::<u16>(&mut read, scroll::LE)?) * 8;
                UnwindOperation::SaveNonVolatile(register, StackFrameOffset::with_ctx(offset, ctx))
            }
            self::UWOP_SAVE_NONVOL_FAR => {
                let register = Register(operation_info);
                let offset = bytes.gread_with::<u32>(&mut read, scroll::LE)?;
                UnwindOperation::SaveNonVolatile(register, StackFrameOffset::with_ctx(offset, ctx))
            }
            self::UWOP_EPILOG => {
                if ctx.version == 1 {
                    // Version 1: This was UWOP_SAVE_XMM
                    let data = u32::from(bytes.gread_with::<u16>(&mut read, scroll::LE)?) * 16;
                    let register = Register::xmm(operation_info);
                    UnwindOperation::SaveXMM(register, StackFrameOffset::with_ctx(data, ctx))
                } else if ctx.version == 2 {
                    // Version 2: UWOP_EPILOG - describes epilogue locations
                    // See https://github.com/BlancLoup/weekly-geekly.github.io/blob/1cbdf1c6127fcdaeda1f01bcbb006febd17d5a95/articles/322956/index.html
                    // See https://github.com/Montura/cpp/blob/4393c678ee8e44dd98feb7a198c3983a6108cef8/src/exception_handling/msvc/eh_msvc_cxx_EH_x64.md?plain=1#L119
                    UnwindOperation::Epilog {
                        offset_low_or_size: code_offset,
                        offset_high_or_flags: operation_info,
                    }
                } else {
                    let msg = format!(
                        "Unwind info version has to be either one of `1` or `2`: {}",
                        ctx.version
                    );
                    return Err(error::Error::Malformed(msg));
                }
            }
            self::UWOP_SPARE_CODE => {
                let data = bytes.gread_with::<u32>(&mut read, scroll::LE)?;
                if ctx.version == 1 {
                    let register = Register::xmm(operation_info);
                    UnwindOperation::SaveXMM128(register, StackFrameOffset::with_ctx(data, ctx))
                } else if ctx.version == 2 {
                    UnwindOperation::Noop
                } else {
                    let msg = format!(
                        "Unwind info version has to be either one of `1` or `2`: {}",
                        ctx.version
                    );
                    return Err(error::Error::Malformed(msg));
                }
            }
            self::UWOP_SAVE_XMM128 => {
                let register = Register::xmm(operation_info);
                let offset = u32::from(bytes.gread_with::<u16>(&mut read, scroll::LE)?) * 16;
                UnwindOperation::SaveXMM128(register, StackFrameOffset::with_ctx(offset, ctx))
            }
            self::UWOP_SAVE_XMM128_FAR => {
                let register = Register::xmm(operation_info);
                let offset = bytes.gread_with::<u32>(&mut read, scroll::LE)?;
                UnwindOperation::SaveXMM128(register, StackFrameOffset::with_ctx(offset, ctx))
            }
            self::UWOP_PUSH_MACHFRAME => {
                let is_error = match operation_info {
                    0 => false,
                    1 => true,
                    i => {
                        let msg = format!("invalid op info ({}) for UWOP_PUSH_MACHFRAME", i);
                        return Err(error::Error::Malformed(msg));
                    }
                };
                UnwindOperation::PushMachineFrame(is_error)
            }
            op => {
                let msg = format!("unknown unwind op code ({})", op);
                return Err(error::Error::Malformed(msg));
            }
        };

        let code = UnwindCode {
            code_offset,
            operation,
        };

        Ok((code, read))
    }
}

/// An iterator over unwind codes for a function or part of a function, returned from
/// [`UnwindInfo`].
///
/// [`UnwindInfo`]: struct.UnwindInfo.html
#[derive(Clone, Debug)]
pub struct UnwindCodeIterator<'a> {
    bytes: &'a [u8],
    offset: usize,
    context: UnwindOpContext,
}

impl Iterator for UnwindCodeIterator<'_> {
    type Item = error::Result<UnwindCode>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        Some(self.bytes.gread_with(&mut self.offset, self.context))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let upper = (self.bytes.len() - self.offset) / UNWIND_CODE_SIZE;
        // the largest codes take up three slots
        let lower = (upper + 3 - (upper % 3)) / 3;
        (lower, Some(upper))
    }
}

impl FusedIterator for UnwindCodeIterator<'_> {}

/// A language-specific handler that is called as part of the search for an exception handler or as
/// part of an unwind.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum UnwindHandler<'a> {
    /// The image-relative address of an exception handler and its implementation-defined data.
    ExceptionHandler(u32, &'a [u8]),
    /// The image-relative address of a termination handler and its implementation-defined data.
    TerminationHandler(u32, &'a [u8]),
}

/// Unwind information for a function or portion of a function.
///
/// The unwind info structure is used to record the effects a function has on the stack pointer and
/// where the nonvolatile registers are saved on the stack. The unwind codes can be enumerated with
/// [`unwind_codes`].
///
/// This unwind info might only be secondary information, and link to a [chained unwind handler].
/// For unwinding, this link shall be followed until the root unwind info record has been resolved.
///
/// [`unwind_codes`]: struct.UnwindInfo.html#method.unwind_codes
/// [chained unwind handler]: struct.UnwindInfo.html#structfield.chained_info
#[derive(Clone)]
pub struct UnwindInfo<'a> {
    /// Version of this unwind info.
    pub version: u8,

    /// Length of the function prolog in bytes.
    pub size_of_prolog: u8,

    /// The nonvolatile register used as the frame pointer of this function.
    ///
    /// If this register is non-zero, all stack frame offsets used in unwind operations are of type
    /// `StackFrameOffset::FP`. When loading these offsets, they have to be based off the value of
    /// this frame register instead of the conventional RSP. This allows the RSP to be modified.
    pub frame_register: Register,

    /// Offset from RSP that is applied to the FP register when it is established.
    ///
    /// When loading offsets of type `StackFrameOffset::FP` from the stack, this offset has to be
    /// subtracted before loading the value since the actual RSP was lower by that amount in the
    /// prolog.
    pub frame_register_offset: u32,

    /// A record pointing to chained unwind information.
    ///
    /// If chained unwind info is present, then this unwind info is a secondary one and the linked
    /// unwind info contains primary information. Chained info is useful in two situations. First,
    /// it is used for noncontiguous code segments. Second, this mechanism is sometimes used to
    /// group volatile register saves.
    ///
    /// The referenced unwind info can itself specify chained unwind information, until it arrives
    /// at the root unwind info. Generally, the entire chain should be considered when unwinding.
    pub chained_info: Option<RuntimeFunction>,

    /// An exception or termination handler called as part of the unwind.
    pub handler: Option<UnwindHandler<'a>>,

    /// A list of unwind codes, sorted descending by code offset.
    code_bytes: &'a [u8],
}

impl<'a> UnwindInfo<'a> {
    /// Parses unwind information from the image at the given offset.
    pub fn parse(bytes: &'a [u8], mut offset: usize) -> error::Result<Self> {
        // Read the version and flags fields, which are combined into a single byte.
        let version_flags: u8 = bytes.gread_with(&mut offset, scroll::LE)?;
        let version = version_flags & 0b111;
        let flags = version_flags >> 3;

        if version < 1 || version > 2 {
            let msg = format!("unsupported unwind code version ({})", version);
            return Err(error::Error::Malformed(msg));
        }

        let size_of_prolog = bytes.gread_with::<u8>(&mut offset, scroll::LE)?;
        let count_of_codes = bytes.gread_with::<u8>(&mut offset, scroll::LE)?;

        // Parse the frame register and frame register offset values, that are combined into a
        // single byte.
        let frame_info = bytes.gread_with::<u8>(&mut offset, scroll::LE)?;
        // If nonzero, then the function uses a frame pointer (FP), and this field is the number
        // of the nonvolatile register used as the frame pointer. The zero register value does
        // not need special casing since it will not be referenced by the unwind operations.
        let frame_register = Register(frame_info & 0xf);
        // The the scaled offset from RSP that is applied to the FP register when it's
        // established. The actual FP register is set to RSP + 16 * this number, allowing
        // offsets from 0 to 240.
        let frame_register_offset = u32::from((frame_info >> 4) * 16);

        // An array of items that explains the effect of the prolog on the nonvolatile registers and
        // RSP. Some unwind codes require more than one slot in the array.
        let codes_size = count_of_codes as usize * UNWIND_CODE_SIZE;
        let code_bytes = bytes.gread_with(&mut offset, codes_size)?;

        // For alignment purposes, the codes array typically has an even number of entries, and the
        // final entry is potentially unused. In that case, the array is one longer than indicated
        // by the count of unwind codes field.
        //
        // Sometimes, developers decided to handy craft unwind info in their assembly forget to align
        // unwind infos. This is not really desirable behavior for such cases anyway.
        if count_of_codes % 2 != 0 {
            offset += 2;
        }

        let mut chained_info = None;
        let mut handler = None;

        // If flag UNW_FLAG_CHAININFO is set then the UNWIND_INFO structure ends with three UWORDs.
        // These UWORDs represent the RUNTIME_FUNCTION information for the function of the chained
        // unwind.
        if flags & UNW_FLAG_CHAININFO != 0 {
            chained_info = Some(bytes.gread_with(&mut offset, scroll::LE)?);

        // The relative address of the language-specific handler is present in the UNWIND_INFO
        // whenever flags UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER are set. The language-specific
        // handler is called as part of the search for an exception handler or as part of an unwind.
        } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            let address = bytes.gread_with::<u32>(&mut offset, scroll::LE)?;
            if offset > bytes.len() {
                return Err(error::Error::Malformed(format!(
                    "Offset {offset:#x} is too big to contain unwind handlers",
                )));
            }
            let data = &bytes[offset..];

            handler = Some(if flags & UNW_FLAG_EHANDLER != 0 {
                UnwindHandler::ExceptionHandler(address, data)
            } else {
                UnwindHandler::TerminationHandler(address, data)
            });
        }

        Ok(UnwindInfo {
            version,
            size_of_prolog,
            frame_register,
            frame_register_offset,
            chained_info,
            handler,
            code_bytes,
        })
    }

    /// Returns an iterator over unwind codes in this unwind info.
    ///
    /// Unwind codes are iterated in descending `code_offset` order suitable for unwinding. If the
    /// optional [`chained_info`](Self::chained_info) is present, codes of that unwind info should be interpreted
    /// immediately afterwards.
    pub fn unwind_codes(&self) -> UnwindCodeIterator<'a> {
        UnwindCodeIterator {
            bytes: self.code_bytes,
            offset: 0,
            context: UnwindOpContext {
                version: self.version,
                frame_register: self.frame_register,
            },
        }
    }

    /// Returns an iterator over C scope table entries in this unwind info.
    ///
    /// If this unwind info has no [UnwindHandler::ExceptionHandler], this will always return `None`.
    pub fn c_scope_table_entries(&self) -> Option<ScopeTableIterator<'a>> {
        let UnwindHandler::ExceptionHandler(_, data) = self.handler? else {
            return None;
        };
        let mut offset = 0;
        let num_entries = data.gread_with::<u32>(&mut offset, scroll::LE).ok()?;
        let table_size = num_entries * core::mem::size_of::<ScopeTableEntry>() as u32;
        let data = data.pread_with::<&[u8]>(offset, table_size as usize).ok()?;
        Some(ScopeTableIterator { data, offset: 0 })
    }
}

impl fmt::Debug for UnwindInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let count_of_codes = self.code_bytes.len() / UNWIND_CODE_SIZE;

        f.debug_struct("UnwindInfo")
            .field("version", &self.version)
            .field("size_of_prolog", &self.size_of_prolog)
            .field("frame_register", &self.frame_register)
            .field("frame_register_offset", &self.frame_register_offset)
            .field("count_of_codes", &count_of_codes)
            .field("chained_info", &self.chained_info)
            .field("handler", &self.handler)
            .finish()
    }
}

impl<'a> IntoIterator for &'_ UnwindInfo<'a> {
    type Item = error::Result<UnwindCode>;
    type IntoIter = UnwindCodeIterator<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.unwind_codes()
    }
}

/// Exception handling and stack unwind information for functions in the image.
pub struct ExceptionData<'a> {
    bytes: &'a [u8],
    offset: usize,
    size: usize,
    file_alignment: u32,
}

impl<'a> ExceptionData<'a> {
    /// Parses exception data from the image at the given offset.
    pub fn parse(
        bytes: &'a [u8],
        directory: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
    ) -> error::Result<Self> {
        Self::parse_with_opts(
            bytes,
            directory,
            sections,
            file_alignment,
            &options::ParseOptions::default(),
        )
    }

    /// Parses exception data from the image at the given offset.
    pub fn parse_with_opts(
        bytes: &'a [u8],
        directory: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        opts: &options::ParseOptions,
    ) -> error::Result<Self> {
        let size = directory.size as usize;

        if size % RUNTIME_FUNCTION_SIZE != 0 {
            return Err(error::Error::from(scroll::Error::BadInput {
                size,
                msg: "invalid exception directory table size",
            }));
        }

        let rva = directory.virtual_address as usize;
        let offset = utils::find_offset(rva, sections, file_alignment, opts).ok_or_else(|| {
            error::Error::Malformed(format!("cannot map exception_rva ({:#x}) into offset", rva))
        })?;

        if offset % 4 != 0 {
            return Err(error::Error::from(scroll::Error::BadOffset(offset)));
        }

        Ok(ExceptionData {
            bytes,
            offset,
            size,
            file_alignment,
        })
    }

    /// The number of function entries described by this exception data.
    pub fn len(&self) -> usize {
        self.size / RUNTIME_FUNCTION_SIZE
    }

    /// Indicating whether there are functions in this entry.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterates all function entries in order of their code offset.
    ///
    /// To search for a function by relative instruction address, use [`find_function`]. To resolve
    /// unwind information, use [`get_unwind_info`].
    ///
    /// [`find_function`]: struct.ExceptionData.html#method.find_function
    /// [`get_unwind_info`]: struct.ExceptionData.html#method.get_unwind_info
    pub fn functions(&self) -> RuntimeFunctionIterator<'a> {
        RuntimeFunctionIterator {
            data: &self.bytes[self.offset..self.offset + self.size],
        }
    }

    /// Returns the function at the given index.
    pub fn get_function(&self, index: usize) -> error::Result<RuntimeFunction> {
        self.get_function_by_offset(self.offset + index * RUNTIME_FUNCTION_SIZE)
    }

    /// Returns an iterator over ARM64 runtime function entries.
    pub fn functions_arm64(&self) -> Arm64RuntimeFunctionIterator<'a> {
        Arm64RuntimeFunctionIterator {
            data: &self.bytes[self.offset..self.offset + self.size],
        }
    }

    /// Returns an ARM64 runtime function at the given index.
    pub fn get_function_arm64(&self, index: usize) -> error::Result<Arm64RuntimeFunction> {
        self.get_function_by_offset_arm64(self.offset + index * size_of::<Arm64RuntimeFunction>())
    }

    /// Performs a binary search to find a function entry covering the given RVA relative to the
    /// image.
    pub fn find_function(&self, rva: u32) -> error::Result<Option<RuntimeFunction>> {
        // NB: Binary search implementation copied from std::slice::binary_search_by and adapted.
        // Theoretically, there should be nothing that causes parsing runtime functions to fail and
        // all access to the bytes buffer is guaranteed to be in range. However, since all other
        // functions also return Results, this is much more ergonomic here.

        let mut size = self.len();
        if size == 0 {
            return Ok(None);
        }

        let mut base = 0;
        while size > 1 {
            let half = size / 2;
            let mid = base + half;
            let offset = self.offset + mid * RUNTIME_FUNCTION_SIZE;
            let addr = self.bytes.pread_with::<u32>(offset, scroll::LE)?;
            base = if addr > rva { base } else { mid };
            size -= half;
        }

        let offset = self.offset + base * RUNTIME_FUNCTION_SIZE;
        let addr = self.bytes.pread_with::<u32>(offset, scroll::LE)?;
        let function = match addr.cmp(&rva) {
            Ordering::Less | Ordering::Equal => self.get_function(base)?,
            Ordering::Greater if base == 0 => return Ok(None),
            Ordering::Greater => self.get_function(base - 1)?,
        };

        if function.end_address > rva {
            Ok(Some(function))
        } else {
            Ok(None)
        }
    }

    /// Resolves unwind information for the given function entry.
    pub fn get_unwind_info(
        &self,
        function: RuntimeFunction,
        sections: &[section_table::SectionTable],
    ) -> error::Result<UnwindInfo<'a>> {
        self.get_unwind_info_with_opts(function, sections, &options::ParseOptions::default())
    }

    /// Resolves unwind information for the given ARM64 function entry.
    pub fn get_unwind_info_arm64(
        &self,
        function: Arm64RuntimeFunction,
        sections: &[section_table::SectionTable],
    ) -> Option<error::Result<Arm64UnwindInfo<'a>>> {
        self.get_unwind_info_arm64_with_opts(function, sections, &options::ParseOptions::default())
    }

    /// Resolves unwind information for the given function entry.
    pub fn get_unwind_info_with_opts(
        &self,
        mut function: RuntimeFunction,
        sections: &[section_table::SectionTable],
        opts: &options::ParseOptions,
    ) -> error::Result<UnwindInfo<'a>> {
        while function.unwind_info_address % 2 != 0 {
            let rva = (function.unwind_info_address & !1) as usize;
            function = self.get_function_by_rva_with_opts(rva, sections, opts)?;
        }

        let rva = function.unwind_info_address as usize;
        let offset =
            utils::find_offset(rva, sections, self.file_alignment, opts).ok_or_else(|| {
                error::Error::Malformed(format!("cannot map unwind rva ({:#x}) into offset", rva))
            })?;

        UnwindInfo::parse(self.bytes, offset)
    }

    /// Resolves unwind information for the given ARM64 function entry.
    pub fn get_unwind_info_arm64_with_opts(
        &self,
        function: Arm64RuntimeFunction,
        sections: &[section_table::SectionTable],
        opts: &options::ParseOptions,
    ) -> Option<error::Result<Arm64UnwindInfo<'a>>> {
        if function.flag() == ARM64_PDATA_REF_TO_FULL_XDATA {
            let rva = function.unwind_data_rva() as usize;
            let offset = match utils::find_offset(rva, sections, self.file_alignment, opts)
                .ok_or_else(|| {
                    error::Error::Malformed(format!("cannot map unwind rva ({rva:#x}) into offset"))
                }) {
                Ok(v) => v,
                Err(err) => return Some(Err(err)),
            };
            Some(Arm64UnwindInfo::parse(self.bytes, offset))
        } else {
            // Unwind info is packed into the runtime function entry.
            None
        }
    }

    #[allow(dead_code)]
    fn get_function_by_rva(
        &self,
        rva: usize,
        sections: &[section_table::SectionTable],
    ) -> error::Result<RuntimeFunction> {
        self.get_function_by_rva_with_opts(rva, sections, &options::ParseOptions::default())
    }

    fn get_function_by_rva_with_opts(
        &self,
        rva: usize,
        sections: &[section_table::SectionTable],
        opts: &options::ParseOptions,
    ) -> error::Result<RuntimeFunction> {
        let offset =
            utils::find_offset(rva, sections, self.file_alignment, opts).ok_or_else(|| {
                error::Error::Malformed(format!(
                    "cannot map exception rva ({:#x}) into offset",
                    rva
                ))
            })?;

        self.get_function_by_offset(offset)
    }

    #[inline]
    fn get_function_by_offset(&self, offset: usize) -> error::Result<RuntimeFunction> {
        debug_assert!((offset - self.offset) % RUNTIME_FUNCTION_SIZE == 0);
        debug_assert!(offset < self.offset + self.size);

        Ok(self.bytes.pread_with(offset, scroll::LE)?)
    }

    #[inline]
    fn get_function_by_offset_arm64(&self, offset: usize) -> error::Result<Arm64RuntimeFunction> {
        debug_assert!((offset - self.offset) % size_of::<Arm64RuntimeFunction>() == 0);
        debug_assert!(offset < self.offset + self.size);

        Ok(self.bytes.pread_with(offset, scroll::LE)?)
    }
}

impl fmt::Debug for ExceptionData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExceptionData")
            .field("file_alignment", &self.file_alignment)
            .field("offset", &format_args!("{:#x}", self.offset))
            .field("size", &format_args!("{:#x}", self.size))
            .field("len", &self.len())
            .finish()
    }
}

impl<'a> IntoIterator for &'_ ExceptionData<'a> {
    type Item = error::Result<RuntimeFunction>;
    type IntoIter = RuntimeFunctionIterator<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.functions()
    }
}

// Arm64RuntimeFunction::flag

/// `unwind_data` is an RVA to a full unwind record.
pub const ARM64_PDATA_REF_TO_FULL_XDATA: u32 = 0;
/// `unwind_data` uses the packed unwind data for a function.
pub const ARM64_PDATA_PACKED_UNWIND_FUNCTION: u32 = 1;
/// `unwind_data` uses the packed unwind data for a fragment.
pub const ARM64_PDATA_PACKED_UNWIND_FRAGMENT: u32 = 2;

// Arm64RuntimeFunction::cr

/// Unchained function `<x29, lr>` pair is not saved on the stack.
pub const ARM64_PDATA_CR_UNCHAINED: u32 = 0;
/// Unchained function but `lr` is saved on the stack.
pub const ARM64_PDATA_CR_UNCHAINED_SAVED_LR: u32 = 1;
/// Chained function with PAC (Pointer Authentication Code).
pub const ARM64_PDATA_CR_CHAINED_WITH_PAC: u32 = 2;
/// Chained function.
pub const ARM64_PDATA_CR_CHAINED: u32 = 3;

// Arm64RuntimeFunction::ret
// this is not relevant for ARM64.

/// Return by `pop {pc}`.
pub const ARM_PDATA_RET_POP_PC: u32 = 0;
/// Return by 16-bit branch.
pub const ARM_PDATA_RET_BRANCH_16: u32 = 1;
/// Return by 32-bit branch.
pub const ARM_PDATA_RET_BRANCH_32: u32 = 2;
/// Return with no epilogue.
pub const ARM_PDATA_RET_NO_EPILOGUE: u32 = 3;

/// An ARM64 unwind entry for a range.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Default, Pread, Pwrite)]
pub struct Arm64RuntimeFunction {
    /// Function start RVA.
    pub begin_address: u32,
    /// Unwind data for this function entry.
    pub unwind_data: u32,
}

const _: () = assert!(size_of::<Arm64RuntimeFunction>() == 8);

impl Arm64RuntimeFunction {
    const fn mask(bits: u32) -> u32 {
        (1u32 << bits) - 1
    }

    const fn bits(v: u32, shr: u32, bits: u32) -> u32 {
        (v >> shr) & Self::mask(bits)
    }

    /// If zero, unwind data is an RVA, packed into the runtime function entry otherwise.
    ///
    /// Must be one of:
    /// - [ARM64_PDATA_REF_TO_FULL_XDATA]
    /// - [ARM64_PDATA_PACKED_UNWIND_FUNCTION]
    /// - [ARM64_PDATA_PACKED_UNWIND_FRAGMENT]
    pub const fn flag(&self) -> u32 {
        Self::bits(self.unwind_data, 0, 2)
    }

    /// Returns the length of the function in bytes.
    pub const fn function_length(&self) -> u32 {
        Self::bits(self.unwind_data, 2, 11).wrapping_mul(4)
    }

    /// Returns the frame size in bytes.
    pub const fn frame_size(&self) -> u32 {
        Self::bits(self.unwind_data, 13, 9).wrapping_mul(16)
    }

    /// Returns bits indicates saved FP/SIMD register info.
    pub const fn reg_f(&self) -> u32 {
        Self::bits(self.unwind_data, 13, 3)
    }

    /// Returns bits indicates saved integer register info.
    pub const fn reg_i(&self) -> u32 {
        Self::bits(self.unwind_data, 16, 4)
    }

    /// Returns bits indicates epilog info.
    pub const fn ret(&self) -> u32 {
        Self::bits(self.unwind_data, 13, 2)
    }

    /// Returns `true` if the function homes registers.
    pub const fn h(&self) -> bool {
        Self::bits(self.unwind_data, 20, 1) != 0
    }

    /// Returns bits indicates frame chaining / LR handling.
    pub const fn cr(&self) -> u32 {
        Self::bits(self.unwind_data, 21, 2)
    }

    /// Returns the stack adjustment in bytes.
    pub const fn stack_adjust(&self) -> u32 {
        Self::bits(self.unwind_data, 23, 9).wrapping_mul(16)
    }

    /// Returns `true` if this unwind data is packed, `false` otherwise.
    pub const fn is_packed(&self) -> bool {
        self.flag() != ARM64_PDATA_REF_TO_FULL_XDATA
    }

    /// Returns an RVA of the full unwind data.
    pub const fn unwind_data_rva(&self) -> u32 {
        self.unwind_data & !Self::mask(2)
    }
}

impl fmt::Debug for Arm64RuntimeFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Arm64RuntimeFunction")
            .field("begin_address", &format_args!("{:#x}", self.begin_address))
            .field("unwind_data", &format_args!("{:#x}", self.unwind_data))
            .finish()
    }
}

/// Iterator over [Arm64RuntimeFunction] ARM64 runtime function entries.
#[derive(Debug)]
pub struct Arm64RuntimeFunctionIterator<'a> {
    data: &'a [u8],
}

impl Iterator for Arm64RuntimeFunctionIterator<'_> {
    type Item = error::Result<Arm64RuntimeFunction>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        Some(match self.data.pread_with(0, scroll::LE) {
            Ok(func) => {
                self.data = &self.data[size_of::<Arm64RuntimeFunction>()..];
                Ok(func)
            }
            Err(error) => {
                self.data = &[];
                Err(error.into())
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.data.len() / size_of::<Arm64RuntimeFunction>();
        (len, Some(len))
    }
}

impl FusedIterator for Arm64RuntimeFunctionIterator<'_> {}
impl ExactSizeIterator for Arm64RuntimeFunctionIterator<'_> {}

/// ARM64 unwind info header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm64UnwindHeader(pub u32);

const _: () = assert!(size_of::<Arm64UnwindHeader>() == 4);

impl Arm64UnwindHeader {
    const fn mask(bits: u32) -> u32 {
        (1u32 << bits) - 1
    }

    const fn bits(v: u32, shr: u32, bits: u32) -> u32 {
        (v >> shr) & Self::mask(bits)
    }

    /// Returns a function length in bytes.
    pub const fn function_length(&self) -> u32 {
        Self::bits(self.0, 0, 18).wrapping_mul(4)
    }

    /// Returns an unwind info version.
    pub const fn version(&self) -> u32 {
        Self::bits(self.0, 18, 2)
    }

    /// Returns `true` if the unwind info has exception handler.
    pub const fn exception_data_present(&self) -> bool {
        Self::bits(self.0, 20, 1) != 0
    }

    /// Returns `true` if an epilog is in the header.
    pub const fn epilog_in_header(&self) -> bool {
        Self::bits(self.0, 21, 1) != 0
    }

    /// Returns bits indicates either an number of epilog scope or
    /// the index of the first unwind code that describes the epilog.
    pub const fn epilog_count(&self) -> u32 {
        Self::bits(self.0, 22, 5)
    }

    /// Returns the number of u32's with unwind codes.
    pub const fn code_words(&self) -> u32 {
        Self::bits(self.0, 27, 5)
    }

    /// Returns `true` if "extension" bytes are in addition.
    pub const fn has_extension(&self) -> bool {
        self.epilog_count() == 0 && self.code_words() == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm64UnwindExtension(pub u32);

const _: () = assert!(size_of::<Arm64UnwindExtension>() == 4);

impl Arm64UnwindExtension {
    /// Returns the number of epilog.
    pub const fn epilog_count(&self) -> u32 {
        (self.0 & 0xFFFF) as u32
    }

    /// Returns the number of u32's with unwind codes.
    pub const fn code_words(&self) -> u32 {
        ((self.0 >> 16) & 0xFF) as u32
    }
}

/// ARM64 epilog scope info.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm64EpilogScope(pub u32);

const _: () = assert!(size_of::<Arm64EpilogScope>() == 4);

impl Arm64EpilogScope {
    const fn mask(bits: u32) -> u32 {
        (1u32 << bits) - 1
    }

    const fn bits(v: u32, shr: u32, bits: u32) -> u32 {
        (v >> shr) & Self::mask(bits)
    }

    /// Returns an epulog start offset in bytes.
    pub const fn start_offset_words(&self) -> u32 {
        Self::bits(self.0, 0, 18).wrapping_mul(4)
    }

    /// Returns the bits indicate condition.
    pub const fn condition(&self) -> u32 {
        Self::bits(self.0, 18, 4)
    }

    /// Returns the index of the unwind code.
    pub const fn start_index(&self) -> u32 {
        Self::bits(self.0, 22, 10)
    }
}

/// Iterator over epilog scopes.
#[derive(Debug)]
pub struct Arm64EpilogScopeIterator<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for Arm64EpilogScopeIterator<'_> {
    type Item = error::Result<Arm64EpilogScope>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        Some(
            self.bytes
                .gread_with::<u32>(&mut self.offset, scroll::LE)
                .map(Arm64EpilogScope)
                .map_err(Into::into),
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = (self.bytes.len().saturating_sub(self.offset)) / size_of_val(&0u32);
        (len, Some(len))
    }
}

impl FusedIterator for Arm64EpilogScopeIterator<'_> {}
impl ExactSizeIterator for Arm64EpilogScopeIterator<'_> {}

/// ARM64 exception handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Arm64ExceptionHandler<'a> {
    /// RVA of the exception handler.
    pub rva: u32,
    /// Handler-specific data.
    pub data: &'a [u8],
}

/// ARM64 unwind info.
#[derive(Clone, Debug)]
pub struct Arm64UnwindInfo<'a> {
    /// Unwind info header.
    pub header: Arm64UnwindHeader,
    /// Extension info if present.
    pub extension: Option<Arm64UnwindExtension>,
    /// Bytes of epilog scope.
    epilog_scope_bytes: &'a [u8],
    /// Bytes of unwind codes.
    unwind_code_bytes: &'a [u8],
    /// Exception handler and bytes of handler specific data if present.
    pub exception_handler: Option<Arm64ExceptionHandler<'a>>,
}

impl<'a> Arm64UnwindInfo<'a> {
    fn checked_mul4(words: u32) -> error::Result<usize> {
        let bytes = words
            .checked_mul(4)
            .ok_or_else(|| error::Error::Malformed("arm64 unwind info size overflow".into()))?;
        usize::try_from(bytes)
            .map_err(|_| error::Error::Malformed("arm64 unwind info size overflow".into()))
    }

    fn checked_add(a: usize, b: usize) -> error::Result<usize> {
        a.checked_add(b)
            .ok_or_else(|| error::Error::Malformed("arm64 unwind info size overflow".into()))
    }

    /// Precomputes the size of this xdata. This does _not_ count for handler-specific bytes after handler RVA.
    /// <https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170#xdata-records>
    pub fn size(bytes: &[u8]) -> error::Result<usize> {
        let w0 = bytes.pread_with::<u32>(0, scroll::LE)?;

        let (mut size_u32, epilog_scopes, unwind_words) = if (w0 >> 22) != 0 {
            let size = 4u32;
            let epilog_scopes = (w0 >> 22) & 0x1f;
            let unwind_words = (w0 >> 27) & 0x1f;
            (size, epilog_scopes, unwind_words)
        } else {
            let w1 = bytes.pread_with::<u32>(4, scroll::LE)?;
            let size = 8u32;
            let epilog_scopes = w1 & 0xffff;
            let unwind_words = (w1 >> 16) & 0xff;
            (size, epilog_scopes, unwind_words)
        };

        let epilog_in_header = (w0 & (1u32 << 21)) != 0;
        if !epilog_in_header {
            size_u32 = Self::checked_add(size_u32 as _, Self::checked_mul4(epilog_scopes)?)? as _;
        }

        size_u32 = Self::checked_add(size_u32 as _, Self::checked_mul4(unwind_words)?)? as _;

        let exception_data_present = (w0 & (1u32 << 20)) != 0;
        if exception_data_present {
            size_u32 = Self::checked_add(size_u32 as _, 4)? as _;
        }

        Ok(size_u32 as usize)
    }

    /// Parses a full ARM64 unwind xdata.
    pub fn parse(bytes: &'a [u8], mut offset: usize) -> error::Result<Self> {
        let header_word = bytes.gread_with::<u32>(&mut offset, scroll::LE)?;
        let header = Arm64UnwindHeader(header_word);

        if header.version() != 0 {
            return Err(error::Error::Malformed(format!(
                "unsupported ARM64 .xdata version ({})",
                header.version()
            )));
        }

        let extension = if header.has_extension() {
            let ext_word = bytes.gread_with::<u32>(&mut offset, scroll::LE)?;
            Some(Arm64UnwindExtension(ext_word))
        } else {
            None
        };

        let epilog_scopes = match (header.epilog_in_header(), extension) {
            (false, Some(ext)) => ext.epilog_count(),
            (false, None) => header.epilog_count(),
            (true, _) => 0,
        };

        let unwind_words = if let Some(ext) = extension {
            ext.code_words()
        } else {
            header.code_words()
        };

        let scope_bytes_len = Self::checked_mul4(epilog_scopes)?;
        let epilog_scope_bytes = bytes.gread_with(&mut offset, scope_bytes_len)?;

        let unwind_bytes_len = Self::checked_mul4(unwind_words)?;
        let unwind_code_bytes = bytes.gread_with(&mut offset, unwind_bytes_len)?;

        let exception_handler = if header.exception_data_present() {
            let handler_rva = bytes.gread_with::<u32>(&mut offset, scroll::LE)?;
            let data = bytes.get(offset..).unwrap_or(&[]);
            Some(Arm64ExceptionHandler {
                rva: handler_rva,
                data,
            })
        } else {
            None
        };

        Ok(Self {
            header,
            extension,
            epilog_scope_bytes,
            unwind_code_bytes,
            exception_handler,
        })
    }

    /// Returns an iterator over epilog scope words.
    pub fn epilog_scopes(&self) -> Option<Arm64EpilogScopeIterator<'a>> {
        if self.header.epilog_in_header() || self.epilog_scope_bytes.is_empty() {
            return None;
        }
        Some(Arm64EpilogScopeIterator {
            bytes: self.epilog_scope_bytes,
            offset: 0,
        })
    }

    /// Returns an iterator over unwind codes.
    pub fn unwind_codes(&self, start_index: u16) -> error::Result<Arm64UnwindCodeIterator<'a>> {
        Arm64UnwindCodeIterator::new(self.unwind_code_bytes, start_index as usize)
    }
}

/// Custom stack cases reserved for specific Microsoft unwind opcodes.
///
/// For more info: <https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170#unwind-codes>
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arm64CustomStackCase {
    TrapFrame,
    MachineFrame,
    Context,
    EcContext,
    ClearUnwoundToCall,
}

/// ARM64 unwind codes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arm64UnwindCode {
    AllocSmall {
        size_bytes: u32,
    },
    SaveR19R20Preindexed {
        offset_bytes: u32,
    },
    SaveFpLr {
        offset_bytes: u32,
    },
    SaveFpLrPreindexed {
        offset_bytes: u32,
    },
    AllocMedium {
        size_bytes: u32,
    },
    SaveRegPair {
        first_reg: u8,
        offset_bytes: u32,
    },
    SaveRegPairPreindexed {
        first_reg: u8,
        offset_bytes: u32,
    },
    SaveReg {
        reg: u8,
        offset_bytes: u32,
    },
    SaveRegPreindexed {
        reg: u8,
        offset_bytes: u32,
    },
    SaveLrPair {
        first_reg: u8,
        offset_bytes: u32,
    },
    SaveFRegPair {
        first_reg: u8,
        offset_bytes: u32,
    },
    SaveFRegPairPreindexed {
        first_reg: u8,
        offset_bytes: u32,
    },
    SaveFReg {
        reg: u8,
        offset_bytes: u32,
    },
    SaveFRegPreindexed {
        reg: u8,
        offset_bytes: u32,
    },

    AllocZ {
        count: u8,
    },

    AllocLarge {
        size_bytes: u32,
    },
    SetFp,
    AddFp {
        imm8: u8,
        offset_bytes: u32,
    },
    Nop,
    End,
    EndC,
    SaveNext,

    SaveAnyReg {
        kind: u8,
        pair: bool,
        preindexed: bool,
        reg: u8,
        offset_bytes: u32,
    },

    SaveZReg {
        r: u8,
        o: u16,
    },

    SavePReg {
        r: u8,
        o: u16,
    },

    CustomStack(Arm64CustomStackCase),

    PacSignLr,

    Reserved {
        opcode: u8,
        data: u32,
        data_len: u8,
    },
}

/// Intermediate data to store offset and length of the unwind code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arm64UnwindCodeData {
    /// Offset of this unwind code.
    pub offset: u16,
    /// The unwind code.
    pub code: Arm64UnwindCode,
    /// Length of this unwind code in bytes.
    pub len: u8,
}

/// Iterator over ARM64 unwind codes.
pub struct Arm64UnwindCodeIterator<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Arm64UnwindCodeIterator<'a> {
    /// Create a new iterator starting at `start` (byte index in the MSB-first unwind-byte stream).
    pub fn new(raw_unwind_bytes: &'a [u8], start: usize) -> error::Result<Self> {
        if raw_unwind_bytes.len() % 4 != 0 {
            return Err(error::Error::Malformed("length not a multiple of 4".into()));
        }
        if start > raw_unwind_bytes.len() {
            return Err(error::Error::Malformed("start index out of range".into()));
        }

        Ok(Self {
            bytes: raw_unwind_bytes,
            offset: start,
        })
    }
}

impl<'a> Iterator for Arm64UnwindCodeIterator<'a> {
    type Item = error::Result<Arm64UnwindCodeData>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        macro_rules! fail {
            ($msg:expr) => {{
                self.offset = self.bytes.len();
                return Some(Err($crate::error::Error::Malformed(($msg).into())));
            }};
            ($fmt:literal $(, $args:expr)* $(,)?) => {{
                self.offset = self.bytes.len();
                return Some(Err($crate::error::Error::Malformed(format!($fmt $(, $args)*))));
            }};
        }

        macro_rules! try_read_u8 {
            ($at:expr) => {{
                match self.bytes.pread::<u8>($at) {
                    Ok(v) => v,
                    Err(err) => fail!("{}", err),
                }
            }};
            ($at:expr, $msg:expr) => {{
                match self.bytes.pread::<u8>($at) {
                    Ok(v) => v,
                    Err(_) => fail!($msg),
                }
            }};
            ($at:expr, $fmt:literal $(, $args:expr)* $(,)?) => {{
                match self.bytes.pread::<u8>($at) {
                    Ok(v) => v,
                    Err(_) => fail!($fmt $(, $args)*),
                }
            }};
        }

        // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170#unwind-codes

        let start = self.offset;
        let b0 = try_read_u8!(start);

        let (code, len) = match b0 {
            0x00..=0x1f => {
                let x = (b0 & 0x1f) as u32;
                (
                    Arm64UnwindCode::AllocSmall {
                        size_bytes: x.wrapping_mul(16),
                    },
                    1,
                )
            }

            0x20..=0x3f => {
                let z = (b0 & 0x1f) as u32;
                (
                    Arm64UnwindCode::SaveR19R20Preindexed {
                        offset_bytes: z.wrapping_mul(8),
                    },
                    1,
                )
            }

            0x40..=0x7f => {
                let z = (b0 & 0x3f) as u32;
                (
                    Arm64UnwindCode::SaveFpLr {
                        offset_bytes: z.wrapping_mul(8),
                    },
                    1,
                )
            }

            0x80..=0xbf => {
                let z = (b0 & 0x3f) as u32;
                (
                    Arm64UnwindCode::SaveFpLrPreindexed {
                        offset_bytes: (z.wrapping_add(1)).wrapping_mul(8),
                    },
                    1,
                )
            }

            0xc0..=0xc7 => {
                let r = try_read_u8!(start + 1, "alloc_m is truncated");
                let x = (((b0 & 0x07) as u32) << 8) | (r as u32);
                (
                    Arm64UnwindCode::AllocMedium {
                        size_bytes: x.wrapping_mul(16),
                    },
                    2,
                )
            }

            0xc8..=0xcb => {
                let b1 = try_read_u8!(start + 1, "save_regp is truncated");
                let x = (((b0 & 0x03) as u32) << 2) | (((b1 >> 6) & 0x03) as u32);
                let z = (b1 & 0x3f) as u32;
                let first_reg = 19u8.wrapping_add(x as u8);
                (
                    Arm64UnwindCode::SaveRegPair {
                        first_reg,
                        offset_bytes: z.wrapping_mul(8),
                    },
                    2,
                )
            }

            0xcc..=0xcf => {
                let b1 = try_read_u8!(start + 1, "save_regp_x is truncated");
                let x = (((b0 & 0x03) as u32) << 2) | (((b1 >> 6) & 0x03) as u32);
                let z = (b1 & 0x3f) as u32;
                let first_reg = 19u8.wrapping_add(x as u8);
                (
                    Arm64UnwindCode::SaveRegPairPreindexed {
                        first_reg,
                        offset_bytes: (z.wrapping_add(1)).wrapping_mul(8),
                    },
                    2,
                )
            }

            0xd0..=0xd3 => {
                let b1 = try_read_u8!(start + 1, "save_reg is truncated");
                let x = (((b0 & 0x03) as u32) << 2) | (((b1 >> 6) & 0x03) as u32);
                let z = (b1 & 0x3f) as u32;
                let reg = 19u8.wrapping_add(x as u8);
                (
                    Arm64UnwindCode::SaveReg {
                        reg,
                        offset_bytes: z.wrapping_mul(8),
                    },
                    2,
                )
            }

            0xd4..=0xd5 => {
                let b1 = try_read_u8!(start + 1, "save_reg_x is truncated");
                let x = (((b0 & 0x01) as u32) << 3) | (((b1 >> 5) & 0x07) as u32);
                let z = (b1 & 0x1f) as u32;
                let reg = 19u8.wrapping_add(x as u8);
                (
                    Arm64UnwindCode::SaveRegPreindexed {
                        reg,
                        offset_bytes: (z.wrapping_add(1)).wrapping_mul(8),
                    },
                    2,
                )
            }

            0xd6..=0xd7 => {
                let b1 = try_read_u8!(start + 1, "save_lrpair is truncated");
                let x = (((b0 & 0x01) as u32) << 2) | (((b1 >> 6) & 0x03) as u32);
                let z = (b1 & 0x3f) as u32;
                let first_reg = 19u8.wrapping_add((2 * x) as u8);
                (
                    Arm64UnwindCode::SaveLrPair {
                        first_reg,
                        offset_bytes: z.wrapping_mul(8),
                    },
                    2,
                )
            }

            0xd8..=0xd9 => {
                let b1 = try_read_u8!(start + 1, "save_fregp is truncated");
                let x = (((b0 & 0x01) as u32) << 2) | (((b1 >> 6) & 0x03) as u32);
                let z = (b1 & 0x3f) as u32;
                let first_reg = 8u8.wrapping_add(x as u8);
                (
                    Arm64UnwindCode::SaveFRegPair {
                        first_reg,
                        offset_bytes: z.wrapping_mul(8),
                    },
                    2,
                )
            }

            0xda..=0xdb => {
                let b1 = try_read_u8!(start + 1, "save_fregp_x is truncated");
                let x = (((b0 & 0x01) as u32) << 2) | (((b1 >> 6) & 0x03) as u32);
                let z = (b1 & 0x3f) as u32;
                let first_reg = 8u8.wrapping_add(x as u8);
                (
                    Arm64UnwindCode::SaveFRegPairPreindexed {
                        first_reg,
                        offset_bytes: (z.wrapping_add(1)).wrapping_mul(8),
                    },
                    2,
                )
            }

            0xdc..=0xdd => {
                let b1 = try_read_u8!(start + 1, "save_freg is truncated");
                let x = (((b0 & 0x01) as u32) << 2) | (((b1 >> 6) & 0x03) as u32);
                let z = (b1 & 0x3f) as u32;
                let reg = 8u8.wrapping_add(x as u8);
                (
                    Arm64UnwindCode::SaveFReg {
                        reg,
                        offset_bytes: z.wrapping_mul(8),
                    },
                    2,
                )
            }

            0xde => {
                let b1 = try_read_u8!(start + 1, "save_freg_x is truncated");
                let x = ((b1 >> 5) & 0x07) as u32;
                let z = (b1 & 0x1f) as u32;
                let reg = 8u8.wrapping_add(x as u8);
                (
                    Arm64UnwindCode::SaveFRegPreindexed {
                        reg,
                        offset_bytes: (z.wrapping_add(1)).wrapping_mul(8),
                    },
                    2,
                )
            }

            0xdf => {
                let z = try_read_u8!(start + 1, "alloc_z is truncated");
                (Arm64UnwindCode::AllocZ { count: z }, 2)
            }

            0xe0 => {
                let imm = {
                    let b0 = try_read_u8!(start + 1) as u32;
                    let b1 = try_read_u8!(start + 2) as u32;
                    let b2 = try_read_u8!(start + 3) as u32;

                    (b0 << 16) | (b1 << 8) | b2
                };
                (
                    Arm64UnwindCode::AllocLarge {
                        size_bytes: imm.wrapping_mul(16),
                    },
                    4,
                )
            }

            0xe1 => (Arm64UnwindCode::SetFp, 1),

            0xe2 => {
                let imm8 = try_read_u8!(start + 1, "add_fp is truncated");
                (
                    Arm64UnwindCode::AddFp {
                        imm8,
                        offset_bytes: (imm8 as u32).wrapping_mul(8),
                    },
                    2,
                )
            }

            0xe3 => (Arm64UnwindCode::Nop, 1),
            0xe4 => (Arm64UnwindCode::End, 1),
            0xe5 => (Arm64UnwindCode::EndC, 1),
            0xe6 => (Arm64UnwindCode::SaveNext, 1),

            0xe7 => {
                let b1 = try_read_u8!(start + 1);

                if (b1 & 0x80) != 0 {
                    let data = b1 as u32;
                    (
                        Arm64UnwindCode::Reserved {
                            opcode: 0xe7,
                            data,
                            data_len: 1,
                        },
                        2,
                    )
                } else {
                    let b2 = try_read_u8!(start + 2, "save_any_? is truncated");

                    let cls = (b2 >> 6) & 0x03;
                    if cls != 3 {
                        let p = ((b1 >> 6) & 1) != 0;
                        let x = ((b1 >> 5) & 1) != 0;
                        let r = (b1 & 0x1f) as u8;
                        let o = (b2 & 0x3f) as u32;

                        let offset_bytes = match (cls, x || p) {
                            (0 | 1, true) => match o.checked_mul(16) {
                                Some(v) => v,
                                None => fail!("save_any_reg offset overflow"),
                            },
                            (0 | 1, false) => match o.checked_mul(8) {
                                Some(v) => v,
                                None => fail!("save_any_reg offset overflow"),
                            },
                            (2, _) => match o.checked_mul(16) {
                                Some(v) => v,
                                None => fail!("save_any_reg offset overflow"),
                            },
                            _ => 0,
                        };

                        let kind = cls as u8;
                        (
                            Arm64UnwindCode::SaveAnyReg {
                                kind,
                                pair: p,
                                preindexed: x,
                                reg: r,
                                offset_bytes,
                            },
                            3,
                        )
                    } else {
                        let hi = ((b1 >> 5) & 0x03) as u16;
                        let r = (b1 & 0x0f) as u8;
                        let lo = (b2 & 0x3f) as u16;
                        let o = (hi << 6) | lo;

                        if (b1 & 0x10) != 0 {
                            (Arm64UnwindCode::SavePReg { r, o }, 3)
                        } else {
                            (Arm64UnwindCode::SaveZReg { r, o }, 3)
                        }
                    }
                }
            }

            0xe8 => (
                Arm64UnwindCode::CustomStack(Arm64CustomStackCase::TrapFrame),
                1,
            ),
            0xe9 => (
                Arm64UnwindCode::CustomStack(Arm64CustomStackCase::MachineFrame),
                1,
            ),
            0xea => (
                Arm64UnwindCode::CustomStack(Arm64CustomStackCase::Context),
                1,
            ),
            0xeb => (
                Arm64UnwindCode::CustomStack(Arm64CustomStackCase::EcContext),
                1,
            ),
            0xec => (
                Arm64UnwindCode::CustomStack(Arm64CustomStackCase::ClearUnwoundToCall),
                1,
            ),

            0xfc => (Arm64UnwindCode::PacSignLr, 1),

            0xf8 => {
                let b1 = try_read_u8!(start + 1);
                (
                    Arm64UnwindCode::Reserved {
                        opcode: 0xf8,
                        data: b1 as u32,
                        data_len: 1,
                    },
                    2,
                )
            }
            0xf9 => {
                let b1 = try_read_u8!(start + 1);
                let b2 = try_read_u8!(start + 2);
                let data = ((b1 as u32) << 8) | (b2 as u32);
                (
                    Arm64UnwindCode::Reserved {
                        opcode: 0xf9,
                        data,
                        data_len: 2,
                    },
                    3,
                )
            }
            0xfa => {
                let b1 = try_read_u8!(start + 1);
                let b2 = try_read_u8!(start + 2);
                let b3 = try_read_u8!(start + 3);
                let data = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
                (
                    Arm64UnwindCode::Reserved {
                        opcode: 0xfa,
                        data,
                        data_len: 3,
                    },
                    4,
                )
            }
            0xfb => {
                let b1 = try_read_u8!(start + 1);
                let b2 = try_read_u8!(start + 2);
                let b3 = try_read_u8!(start + 3);
                let b4 = try_read_u8!(start + 4);
                let data =
                    ((b1 as u32) << 24) | ((b2 as u32) << 16) | ((b3 as u32) << 8) | (b4 as u32);
                (
                    Arm64UnwindCode::Reserved {
                        opcode: 0xfb,
                        data,
                        data_len: 4,
                    },
                    5,
                )
            }

            other => (
                Arm64UnwindCode::Reserved {
                    opcode: other,
                    data: 0,
                    data_len: 0,
                },
                1,
            ),
        };

        self.offset += len;

        Some(Ok(Arm64UnwindCodeData {
            offset: start as u16,
            code,
            len: len as u8,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_of_runtime_function() {
        assert_eq!(
            std::mem::size_of::<RuntimeFunction>(),
            RUNTIME_FUNCTION_SIZE
        );
    }

    // Tests disabled until there is a solution for handling binary test data
    // See https://github.com/m4b/goblin/issues/185

    // macro_rules! microsoft_symbol {
    //     ($name:literal, $id:literal) => {{
    //         use std::fs::File;
    //         use std::path::Path;

    //         let path = Path::new(concat!("cache/", $name));
    //         if !path.exists() {
    //             let url = format!(
    //                 "https://msdl.microsoft.com/download/symbols/{}/{}/{}",
    //                 $name, $id, $name
    //             );

    //             let mut response = reqwest::get(&url).expect(concat!("get ", $name));
    //             let mut target = File::create(path).expect(concat!("create ", $name));
    //             response
    //                 .copy_to(&mut target)
    //                 .expect(concat!("download ", $name));
    //         }

    //         std::fs::read(path).expect(concat!("open ", $name))
    //     }};
    // }

    // lazy_static::lazy_static! {
    //     static ref PE_DATA: Vec<u8> = microsoft_symbol!("WSHTCPIP.DLL", "4a5be0b77000");
    // }

    // #[test]
    // fn test_parse() {
    //     let pe = PE::parse(&PE_DATA).expect("parse PE");
    //     let exception_data = pe.exception_data.expect("get exception data");

    //     assert_eq!(exception_data.len(), 19);
    //     assert!(!exception_data.is_empty());
    // }

    // #[test]
    // fn test_iter_functions() {
    //     let pe = PE::parse(&PE_DATA).expect("parse PE");
    //     let exception_data = pe.exception_data.expect("get exception data");

    //     let functions: Vec<RuntimeFunction> = exception_data
    //         .functions()
    //         .map(|result| result.expect("parse runtime function"))
    //         .collect();

    //     assert_eq!(functions.len(), 19);

    //     let expected = RuntimeFunction {
    //         begin_address: 0x1355,
    //         end_address: 0x1420,
    //         unwind_info_address: 0x4019,
    //     };

    //     assert_eq!(functions[4], expected);
    // }

    // #[test]
    // fn test_get_function() {
    //     let pe = PE::parse(&PE_DATA).expect("parse PE");
    //     let exception_data = pe.exception_data.expect("get exception data");

    //     let expected = RuntimeFunction {
    //         begin_address: 0x1355,
    //         end_address: 0x1420,
    //         unwind_info_address: 0x4019,
    //     };

    //     assert_eq!(
    //         exception_data.get_function(4).expect("find function"),
    //         expected
    //     );
    // }

    // #[test]
    // fn test_find_function() {
    //     let pe = PE::parse(&PE_DATA).expect("parse PE");
    //     let exception_data = pe.exception_data.expect("get exception data");

    //     let expected = RuntimeFunction {
    //         begin_address: 0x1355,
    //         end_address: 0x1420,
    //         unwind_info_address: 0x4019,
    //     };

    //     assert_eq!(
    //         exception_data.find_function(0x1400).expect("find function"),
    //         Some(expected)
    //     );
    // }

    // #[test]
    // fn test_find_function_none() {
    //     let pe = PE::parse(&PE_DATA).expect("parse PE");
    //     let exception_data = pe.exception_data.expect("get exception data");

    //     // 0x1d00 is the end address of the last function.

    //     assert_eq!(
    //         exception_data.find_function(0x1d00).expect("find function"),
    //         None
    //     );
    // }

    // #[test]
    // fn test_get_unwind_info() {
    //     let pe = PE::parse(&PE_DATA).expect("parse PE");
    //     let exception_data = pe.exception_data.expect("get exception data");

    //     // runtime function #0 directly refers to unwind info
    //     let rt_function = RuntimeFunction {
    //         begin_address: 0x1010,
    //         end_address: 0x1090,
    //         unwind_info_address: 0x25d8,
    //     };

    //     let unwind_info = exception_data
    //         .get_unwind_info(rt_function, &pe.sections)
    //         .expect("get unwind info");

    //     // Unwind codes just used to assert that the right unwind info was resolved
    //     let expected = &[4, 98];

    //     assert_eq!(unwind_info.code_bytes, expected);
    // }

    // #[test]
    // fn test_get_unwind_info_redirect() {
    //     let pe = PE::parse(&PE_DATA).expect("parse PE");
    //     let exception_data = pe.exception_data.expect("get exception data");

    //     // runtime function #4 has a redirect (unwind_info_address & 1).
    //     let rt_function = RuntimeFunction {
    //         begin_address: 0x1355,
    //         end_address: 0x1420,
    //         unwind_info_address: 0x4019,
    //     };

    //     let unwind_info = exception_data
    //         .get_unwind_info(rt_function, &pe.sections)
    //         .expect("get unwind info");

    //     // Unwind codes just used to assert that the right unwind info was resolved
    //     let expected = &[
    //         28, 100, 15, 0, 28, 84, 14, 0, 28, 52, 12, 0, 28, 82, 24, 240, 22, 224, 20, 208, 18,
    //         192, 16, 112,
    //     ];

    //     assert_eq!(unwind_info.code_bytes, expected);
    // }

    #[test]
    fn test_unwind_codes_one_epilog() {
        // ; Prologue
        // .text:00000001400884E0 000 57        push    rdi // Save RDI
        //
        // .text:00000001400884E1 008 8B C2     mov     eax, edx
        // .text:00000001400884E3 008 48 8B F9  mov     rdi, rcx
        // .text:00000001400884E6 008 49 8B C8  mov     rcx, r8
        // .text:00000001400884E9 008 F3 AA     rep stosb
        // .text:00000001400884EB 008 49 8B C1  mov     rax, r9
        //
        // ; Epilogue
        // .text:00000001400884EE 008 5F        pop     rdi // Restore RDI
        // .text:00000001400884EF 000 C3        retn

        const BYTES: &[u8] = &[
            0x02, 0x01, 0x03, 0x00, // UNWIND_INFO_HDR <2, 0, 1, 3, 0, 0>
            0x02, 0x16, // UNWIND_CODE <<2, 6, 1>> ; UWOP_EPILOG
            0x00, 0x06, // UNWIND_CODE <<0, 6, 0>> ; UWOP_EPILOG
            0x01, 0x70, // UNWIND_CODE <<1, 0, 7>> ; UWOP_PUSH_NONVOL
        ];

        let unwind_info = UnwindInfo::parse(BYTES, 0).unwrap();
        let unwind_codes: Vec<UnwindCode> = unwind_info
            .unwind_codes()
            .map(|result| result.expect("Unable to parse unwind code"))
            .collect();
        assert_eq!(unwind_codes.len(), 3);
        assert_eq!(
            unwind_codes,
            [
                UnwindCode {
                    code_offset: 2,
                    operation: UnwindOperation::Epilog {
                        offset_low_or_size: 2,
                        offset_high_or_flags: 1,
                    },
                },
                UnwindCode {
                    code_offset: 0,
                    operation: UnwindOperation::Epilog {
                        offset_low_or_size: 0,
                        offset_high_or_flags: 0,
                    },
                },
                UnwindCode {
                    code_offset: 1,
                    operation: UnwindOperation::PushNonVolatile(Register(7)), // RDI
                },
            ]
        );
    }

    #[test]
    fn test_unwind_codes_two_epilog() {
        // ; Prologue
        // .text:00000001400889A0 000 57        push    rdi // Save RDI
        // .text:00000001400889A1 008 56        push    rsi // Save RSI
        //
        // .text:00000001400889A2 010 48 8B F9  mov     rdi, rcx
        // .text:00000001400889A5 010 48 8B F2  mov     rsi, rdx
        // .text:00000001400889A8 010 49 8B C8  mov     rcx, r8
        // .text:00000001400889AB 010 F3 A4     rep movsb
        //
        // ; Epilogue
        // .text:00000001400889AD 010 5E        pop     rsi // Restore RSI
        // .text:00000001400889AE 008 5F        pop     rdi // Restore RDI
        // .text:00000001400889AF 000 C3        retn

        const BYTES: &[u8] = &[
            0x02, 0x02, 0x04, 0x00, // $xdatasym_5     UNWIND_INFO_HDR <2, 0, 2, 4, 0, 0>
            0x03, 0x16, // UNWIND_CODE <<3, 6, 1>> ; UWOP_EPILOG
            0x00, 0x06, // UNWIND_CODE <<0, 6, 0>> ; UWOP_EPILOG
            0x02, 0x60, // UNWIND_CODE <<2, 0, 6>> ; UWOP_PUSH_NONVOL
            0x01, 0x70, // UNWIND_CODE <<1, 0, 7>> ; UWOP_PUSH_NONVOL
        ];

        let unwind_info = UnwindInfo::parse(BYTES, 0).unwrap();
        let unwind_codes: Vec<UnwindCode> = unwind_info
            .unwind_codes()
            .map(|result| result.expect("Unable to parse unwind code"))
            .collect();
        assert_eq!(unwind_codes.len(), 4);
        assert_eq!(
            unwind_codes,
            [
                UnwindCode {
                    code_offset: 3,
                    operation: UnwindOperation::Epilog {
                        offset_low_or_size: 3,
                        offset_high_or_flags: 1,
                    },
                },
                UnwindCode {
                    code_offset: 0,
                    operation: UnwindOperation::Epilog {
                        offset_low_or_size: 0,
                        offset_high_or_flags: 0,
                    },
                },
                UnwindCode {
                    code_offset: 2,
                    operation: UnwindOperation::PushNonVolatile(Register(6)), // RSI
                },
                UnwindCode {
                    code_offset: 1,
                    operation: UnwindOperation::PushNonVolatile(Register(7)), // RDI
                },
            ]
        );
    }

    #[test]
    fn test_iter_unwind_codes() {
        let unwind_info = UnwindInfo {
            version: 1,
            size_of_prolog: 4,
            frame_register: Register(0),
            frame_register_offset: 0,
            chained_info: None,
            handler: None,
            code_bytes: &[4, 98],
        };

        let unwind_codes: Vec<UnwindCode> = unwind_info
            .unwind_codes()
            .map(|result| result.expect("parse unwind code"))
            .collect();

        assert_eq!(unwind_codes.len(), 1);

        let expected = UnwindCode {
            code_offset: 4,
            operation: UnwindOperation::Alloc(56),
        };

        assert_eq!(unwind_codes[0], expected);
    }

    #[rustfmt::skip]
    const UNWIND_INFO_C_SCOPE_TABLE: &[u8] = &[
        // UNWIND_INFO_HDR
        0x09, 0x0F, 0x06, 0x00,

        // UNWIND_CODEs
        0x0F, 0x64,             // UWOP_SAVE_NONVOL (Offset=6, Reg=0x0F)
        0x09, 0x00,
        0x0F, 0x34,             // UWOP_SAVE_NONVOL (Offset=3, Reg=0x0F)
        0x08, 0x00,
        0x0F, 0x52,             // UWOP_ALLOC_SMALL (Size = (2 * 8) + 8 = 24 bytes)
        0x0B, 0x70,             // UWOP_PUSH_NONVOL (Reg=0x0B)

        // Exception handler RVA
        0xC0, 0x1F, 0x00, 0x00, // __C_specific_handler

        // Scope count
        0x02, 0x00, 0x00, 0x00, // Scope table count = 2

        // First C_SCOPE_TABLE entry
        0x01, 0x15, 0x00, 0x00, // BeginAddress   = 0x00001501
        0x06, 0x16, 0x00, 0x00, // EndAddress     = 0x00001606
        0x76, 0x1F, 0x00, 0x00, // HandlerAddress = 0x00001F76
        0x06, 0x16, 0x00, 0x00, // JumpTarget     = 0x00001606

        // Second C_SCOPE_TABLE entry
        0x3A, 0x16, 0x00, 0x00, // BeginAddress   = 0x0000163A
        0x4C, 0x16, 0x00, 0x00, // EndAddress     = 0x0000164C
        0x76, 0x1F, 0x00, 0x00, // HandlerAddress = 0x00001F76
        0x06, 0x16, 0x00, 0x00, // JumpTarget     = 0x00001606
    ];

    #[rustfmt::skip]
    const UNWIND_INFO_C_SCOPE_TABLE_INVALID: &[u8] = &[
        // UNWIND_INFO_HDR
        0x09, 0x0F, 0x06, 0x00,

        // UNWIND_CODEs
        0x0F, 0x64,             // UWOP_SAVE_NONVOL (Offset=6, Reg=0x0F)
        0x09, 0x00,
        0x0F, 0x34,             // UWOP_SAVE_NONVOL (Offset=3, Reg=0x0F)
        0x08, 0x00,
        0x0F, 0x52,             // UWOP_ALLOC_SMALL (Size = (2 * 8) + 8 = 24 bytes)
        0x0B, 0x70,             // UWOP_PUSH_NONVOL (Reg=0x0B)

        // Exception handler RVA
        0xC0, 0x1F, 0x00, 0x00, // __C_specific_handler

        // Scope count
        0x02, 0x00, 0x00, 0x00, // Scope table count = 2

        // First C_SCOPE_TABLE entry
        0x01, 0x15, 0x00, 0x00, // BeginAddress   = 0x00001501
        0x06, 0x16, 0x00, 0x00, // EndAddress     = 0x00001606
        0x76, 0x1F, 0x00, 0x00, // HandlerAddress = 0x00001F76
        0x06, 0x16, 0x00, 0x00, // JumpTarget     = 0x00001606

        // Second C_SCOPE_TABLE entry
        0x3A, 0x16, 0x00, 0x00, // BeginAddress   = 0x0000163A
        0x4C, 0x16, 0x00, 0x00, // EndAddress     = 0x0000164C
        0x76, 0x1F, 0x00, 0x00, // HandlerAddress = 0x00001F76
        0x06,                   // JumpTarget     = 0x??????06
    ];

    #[test]
    fn parse_c_scope_table() {
        let unwind_info = UnwindInfo::parse(UNWIND_INFO_C_SCOPE_TABLE, 0)
            .expect("Failed to parse unwind info with C scope table");
        let entries = unwind_info
            .c_scope_table_entries()
            .expect("C scope table should present");
        let entries = entries.collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            ScopeTableEntry {
                begin: 0x00001501,
                end: 0x00001606,
                handler: 0x00001F76,
                target: 0x00001606,
            }
        );
        assert_eq!(
            entries[1],
            ScopeTableEntry {
                begin: 0x0000163A,
                end: 0x0000164C,
                handler: 0x00001F76,
                target: 0x00001606,
            }
        );
    }

    #[test]
    #[should_panic(expected = "C scope table should present")]
    fn malformed_scope_table_is_not_allowed() {
        let unwind_info = UnwindInfo::parse(UNWIND_INFO_C_SCOPE_TABLE_INVALID, 0)
            .expect("Failed to parse unwind info with C scope table");
        unwind_info
            .c_scope_table_entries()
            .expect("C scope table should present");
    }

    #[test]
    #[should_panic(expected = "Scope table is not aligned")]
    fn unaligned_scope_table_is_not_allowed() {
        let it = ScopeTableIterator {
            data: &[0x00, 0x00, 0x00, 0x00, 0x00],
            offset: 0,
        };
        let _ = it.collect::<Vec<_>>();
    }

    mod arm64 {
        use crate::pe::exception::*;

        #[test]
        fn parse_unwind_info_packed() {
            const DATA: &[u8] = &[
                0x78, 0x11, 0x00, 0x00, // begin_address
                0x21, 0x00, 0xE0, 0x00, // unwind_data
            ];

            let func = DATA.pread::<Arm64RuntimeFunction>(0).unwrap();
            assert_eq!(func.begin_address, 0x1178);
            assert_eq!(func.is_packed(), true);
            assert_eq!(func.flag(), ARM64_PDATA_PACKED_UNWIND_FUNCTION);
            assert_eq!(func.function_length(), 32);
            assert_eq!(func.frame_size(), 0x1000);
            assert_eq!(func.cr(), 3);
            assert_eq!(func.h(), false);
            assert_eq!(func.reg_f(), 0);
            assert_eq!(func.reg_i(), 0);
        }

        #[test]
        fn parse_unwind_info_0() {
            #[rustfmt::skip]
            const XDATA: &[u8] = &[
                0x96, 0x00, 0x70, 0x10,

                // Unwind codes
                0xE1,                   // set_fp
                0x87,                   // save_fplr_x
                0xD1, 0x04,             // save_reg
                0xC8, 0x82,             // save_regp
                0x26,                   // save_r19r20_x
                0xE4,                   // end

                // Exception handler and its exception data
                0x8C, 0x1E, 0x00, 0x00, // imagerel __CxxFrameHandler3_0
                0xA0, 0x32, 0x00, 0x00, // exception data
            ];

            let info = Arm64UnwindInfo::parse(XDATA, 0).unwrap();

            // do not count handler-specific dta.
            assert_eq!(
                Arm64UnwindInfo::size(XDATA).unwrap(),
                XDATA.len() - size_of_val(&0u32)
            );

            assert_eq!(info.header.0, 0x10700096);
            assert_eq!(info.header.function_length(), 600);
            assert_eq!(info.header.version(), 0);
            assert_eq!(info.header.exception_data_present(), true);
            assert_eq!(info.header.epilog_in_header(), true);
            assert_eq!(info.header.epilog_count(), 1);
            assert_eq!(info.header.code_words(), 2);
            assert_eq!(info.header.has_extension(), false);

            assert_eq!(info.unwind_code_bytes, &XDATA[4..12]);

            let codes = info.unwind_codes(0).unwrap();
            let codes = codes.collect::<Vec<_>>();
            assert_eq!(codes.len(), 6);
            assert_eq!(
                codes[0].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 0,
                    code: Arm64UnwindCode::SetFp,
                    len: 1,
                }
            );
            assert_eq!(
                codes[1].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 1,
                    code: Arm64UnwindCode::SaveFpLrPreindexed { offset_bytes: 64 },
                    len: 1,
                }
            );
            assert_eq!(
                codes[2].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 2,
                    code: Arm64UnwindCode::SaveReg {
                        reg: 23,
                        offset_bytes: 32,
                    },
                    len: 2,
                }
            );
            assert_eq!(
                codes[3].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 4,
                    code: Arm64UnwindCode::SaveRegPair {
                        first_reg: 21,
                        offset_bytes: 16,
                    },
                    len: 2,
                }
            );
            assert_eq!(
                codes[4].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 6,
                    code: Arm64UnwindCode::SaveR19R20Preindexed { offset_bytes: 48 },
                    len: 1,
                }
            );
            assert_eq!(
                codes[5].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 7,
                    code: Arm64UnwindCode::End,
                    len: 1,
                }
            );
        }

        #[test]
        fn parse_unwind_info_1() {
            #[rustfmt::skip]
            const XDATA: &[u8] = &[
                0x10, 0x00, 0x50, 0x08,

                // Epilog scopes
                0x0D, 0x00, 0x00, 0x00,

                // Unwind codes
                0x81, // save_fplr_x
                0xE4, // end

                0xE3, 0xE3, // align to 4

                // Exception handler and its exception data
                0x8C, 0x1E, 0x00, 0x00, // imagerel __CxxFrameHandler3_0
                0xA0, 0x32, 0x00, 0x00, // exception data
            ];

            let info = Arm64UnwindInfo::parse(XDATA, 0).unwrap();

            // do not count handler-specific dta.
            assert_eq!(
                Arm64UnwindInfo::size(XDATA).unwrap(),
                XDATA.len() - size_of_val(&0u32)
            );

            assert_eq!(info.header.0, 0x08500010);
            assert_eq!(info.header.version(), 0);
            assert_eq!(info.header.exception_data_present(), true);
            assert_eq!(info.header.epilog_in_header(), false);

            assert_eq!(info.unwind_code_bytes, &XDATA[8..12]);

            let scopes = info.epilog_scopes().unwrap();
            let scopes = scopes.map(Result::unwrap).collect::<Vec<_>>();
            assert_eq!(scopes.len(), 1);
            assert_eq!(scopes[0], Arm64EpilogScope(0x0000000D));

            let codes = info.unwind_codes(0).unwrap();
            let codes = codes.collect::<Vec<_>>();
            assert_eq!(codes.len(), 4);

            assert_eq!(
                codes[0].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 0,
                    code: Arm64UnwindCode::SaveFpLrPreindexed { offset_bytes: 16 },
                    len: 1,
                }
            );
            assert_eq!(
                codes[1].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 1,
                    code: Arm64UnwindCode::End,
                    len: 1,
                }
            );
            assert_eq!(
                // padding
                codes[2].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 2,
                    code: Arm64UnwindCode::Nop,
                    len: 1,
                }
            );
            assert_eq!(
                // padding
                codes[3].as_ref().unwrap(),
                &Arm64UnwindCodeData {
                    offset: 3,
                    code: Arm64UnwindCode::Nop,
                    len: 1,
                }
            );

            assert_eq!(
                info.exception_handler,
                Some(Arm64ExceptionHandler {
                    rva: 0x00001E8C,
                    data: &0x000032A0u32.to_le_bytes()
                })
            );
        }
    }
}
