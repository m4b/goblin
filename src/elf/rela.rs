//! # Relocation computations
//! Below are some common x86_64 relocation computations you might find useful:
//!
//! | Relocation | Value | Size | Formula |
//! |:-----------|:------|:-----|:-------|
//! | R_X86_64_NONE | 0 | none | none |
//! | R_X86_64_64 | 1 | word64 | S + A |
//! | R_X86_64_PC32 | 2 | word32 | S + A - P |
//! | R_X86_64_GOT32 | 3 | word32 | G + A |
//! | R_X86_64_PLT32 | 4 | word32 | L + A - P |
//! | R_X86_64_COPY | 5 | none | none |
//! | R_X86_64_GLOB_DAT | 6 | word64 | S |
//! | R_X86_64_JUMP_SLOT | 7 | word64 | S |
//! | R_X86_64_RELATIVE | 8 | word64 | B + A |
//! | R_X86_64_GOTPCREL | 9 | word32 | G + GOT + A - P |
//! | R_X86_64_32 | 10 | word32 | S + A |
//! | R_X86_64_32S | 11 | word32 | S + A |
//! | R_X86_64_16 | 12 | word16 | S + A |
//! | R_X86_64_PC16 | 13 | word16 | S + A - P |
//! | R_X86_64_8 | 14 | word8 | S + A |
//! | R_X86_64_PC8 | 15 | word8 | S + A - P |
//! | R_X86_64_DTPMOD64 | 16 | word64 | |
//! | R_X86_64_DTPOFF64 | 17 | word64 | |
//! | R_X86_64_TPOFF64 | 18 | word64 | |
//! | R_X86_64_TLSGD | 19 | word32 | |
//! | R_X86_64_TLSLD | 20 | word32 | |
//! | R_X86_64_DTPOFF32 | 21 | word32 | |
//! | R_X86_64_GOTTPOFF | 22 | word32 | |
//! | R_X86_64_TPOFF32 | 23 | word32 | |
//! | R_X86_64_PC64 | 24 | word64 | S + A - P |
//! | R_X86_64_GOTOFF64 | 25 | word64 | S + A - GOT |
//! | R_X86_64_GOTPC32 | 26 | word32 | GOT + A - P |
//! | R_X86_64_SIZE32 | 32 | word32 | Z + A |
//! | R_X86_64_SIZE64 | 33 | word64 | Z + A |
//! | R_X86_64_GOTPC32_TLSDESC | 34 | word32 | |
//! | R_X86_64_TLSDESC_CALL | 35 | none| |
//! | R_X86_64_TLSDESC | 36 | word64×2 | |
//! | R_X86_64_IRELATIVE | 37 | word64 | indirect (B + A) |
//!
//! TLS information is at http://people.redhat.com/aoliva/writeups/TLS/RFC-TLSDESC-x86.txt
//!
//! `R_X86_64_IRELATIVE` is similar to `R_X86_64_RELATIVE` except that
//! the value used in this relocation is the program address returned by the function,
//! which takes no arguments, at the address of the result of the corresponding
//! `R_X86_64_RELATIVE` relocation.

#[cfg(feature = "std")]
pub trait ElfRela {
    /// Address
    fn r_offset(&self) -> u64;
    /// Relocation type and symbol index
    fn r_info(&self) -> u64;
    /// Addend
    fn r_addend(&self) -> i64;
    /// The index into the dynsyms symbol table
    fn r_sym(&self) -> usize;
    /// The relocation type
    fn r_typ(&self) -> u64;
}

// manually passing i32 for now because #27245 is not in stable 1.12 yet
macro_rules! elf_rela {
    ($size:ident, $typ:ty) => {
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Default)]
    pub struct Rela {
      /// Address
      pub r_offset: $size,
      /// Relocation type and symbol index
      pub r_info: $size,
      /// Addend
      pub r_addend: $typ,
    }
    };
    ($size:ident) => {
//      elf_rela!($size, signed_from_unsigned!($size));
    };
}

macro_rules! signed_from_unsigned {
  (u32) => {i32};
  (u64) => {i64}
}

/// No reloc.
pub const R_X86_64_NONE: u64 = 0;
/// Direct 64 bit.
pub const R_X86_64_64: u64 = 1;
/// PC relative 32 bit signed.
pub const R_X86_64_PC32: u64 = 2;
/// 32 bit GOT entry.
pub const R_X86_64_GOT32: u64 = 3;
/// 32 bit PLT address.
pub const R_X86_64_PLT32: u64 = 4;
/// Copy symbol at runtime.
pub const R_X86_64_COPY: u64 = 5;
/// Create GOT entry.
pub const R_X86_64_GLOB_DAT: u64 = 6;
/// Create PLT entry.
pub const R_X86_64_JUMP_SLOT: u64 = 7;
/// Adjust by program base.
pub const R_X86_64_RELATIVE: u64 = 8;
/// 32 bit signed PC relative offset to GOT.
pub const R_X86_64_GOTPCREL: u64 = 9;
/// Direct 32 bit zero extended.
pub const R_X86_64_32: u64 = 10;
/// Direct 32 bit sign extended.
pub const R_X86_64_32S: u64 = 11;
/// Direct 16 bit zero extended.
pub const R_X86_64_16: u64 = 12;
/// 16 bit sign extended pc relative.
pub const R_X86_64_PC16: u64 = 13;
/// Direct 8 bit sign extended.
pub const R_X86_64_8: u64 = 14;
/// 8 bit sign extended pc relative.
pub const R_X86_64_PC8: u64 = 15;
/// ID of module containing symbol.
pub const R_X86_64_DTPMOD64: u64 = 16;
/// Offset in module's TLS block.
pub const R_X86_64_DTPOFF64: u64 = 17;
/// Offset in initial TLS block.
pub const R_X86_64_TPOFF64: u64 = 18;
/// 32 bit signed PC relative offset to two GOT entries for GD symbol.
pub const R_X86_64_TLSGD: u64 = 19;
/// 32 bit signed PC relative offset to two GOT entries for LD symbol.
pub const R_X86_64_TLSLD: u64 = 20;
/// Offset in TLS block.
pub const R_X86_64_DTPOFF32: u64 = 21;
/// 32 bit signed PC relative offset to GOT entry for IE symbol.
pub const R_X86_64_GOTTPOFF: u64 = 22;
/// Offset in initial TLS block.
pub const R_X86_64_TPOFF32: u64 = 23;
/// PC relative 64 bit.
pub const R_X86_64_PC64: u64 = 24;
/// 64 bit offset to GOT.
pub const R_X86_64_GOTOFF64: u64 = 25;
/// 32 bit signed pc relative offset to GOT.
pub const R_X86_64_GOTPC32: u64 = 26;
/// 64-bit GOT entry offset.
pub const R_X86_64_GOT64: u64 = 27;
/// 64-bit PC relative offset to GOT entry.
pub const R_X86_64_GOTPCREL64: u64 = 28;
/// 64-bit PC relative offset to GOT.
pub const R_X86_64_GOTPC64: u64 = 29;
/// like GOT64, says PLT entry needed.
pub const R_X86_64_GOTPLT64: u64 = 30;
/// 64-bit GOT relative offset to PLT entry.
pub const R_X86_64_PLTOFF64: u64 = 31;
/// Size of symbol plus 32-bit addend.
pub const R_X86_64_SIZE32: u64 = 32;
/// Size of symbol plus 64-bit addend.
pub const R_X86_64_SIZE64: u64 = 33;
/// GOT offset for TLS descriptor..
pub const R_X86_64_GOTPC32_TLSDESC: u64 = 34;
/// Marker for call through TLS descriptor..
pub const R_X86_64_TLSDESC_CALL: u64 = 35;
/// TLS descriptor..
pub const R_X86_64_TLSDESC: u64 = 36;
/// Adjust indirectly by program base.
pub const R_X86_64_IRELATIVE: u64 = 37;
/// 64-bit adjust by program base.
pub const R_X86_64_RELATIVE64: u64 = 38;
pub const R_X86_64_NUM: u64 = 39;

#[inline]
pub fn type_to_str(typ: u64) -> &'static str {
    match typ {
        R_X86_64_NONE => "NONE",
        R_X86_64_64 => "64",
        R_X86_64_PC32 => "PC32",
        R_X86_64_GOT32 => "GOT32",
        R_X86_64_PLT32 => "PLT32",
        R_X86_64_COPY => "COPY",
        R_X86_64_GLOB_DAT => "GLOB_DAT",
        R_X86_64_JUMP_SLOT => "JUMP_SLOT",
        R_X86_64_RELATIVE => "RELATIVE",
        R_X86_64_GOTPCREL => "GOTPCREL",
        R_X86_64_32 => "32",
        R_X86_64_32S => "32S",
        R_X86_64_16 => "16",
        R_X86_64_PC16 => "PC16",
        R_X86_64_8 => "8",
        R_X86_64_PC8 => "PC8",
        R_X86_64_DTPMOD64 => "DTPMOD64",
        R_X86_64_DTPOFF64 => "DTPOFF64",
        R_X86_64_TPOFF64 => "TPOFF64",
        R_X86_64_TLSGD => "TLSGD",
        R_X86_64_TLSLD => "TLSLD",
        R_X86_64_DTPOFF32 => "DTPOFF32",
        R_X86_64_GOTTPOFF => "GOTTPOFF",
        R_X86_64_TPOFF32 => "TPOFF32",
        R_X86_64_PC64 => "PC64",
        R_X86_64_GOTOFF64 => "GOTOFF64",
        R_X86_64_GOTPC32 => "GOTPC32",
        R_X86_64_GOT64 => "GOT64",
        R_X86_64_GOTPCREL64 => "GOTPCREL64",
        R_X86_64_GOTPC64 => "GOTPC64",
        R_X86_64_GOTPLT64 => "GOTPLT64",
        R_X86_64_PLTOFF64 => "PLTOFF64",
        R_X86_64_SIZE32 => "SIZE32",
        R_X86_64_SIZE64 => "SIZE64",
        R_X86_64_GOTPC32_TLSDESC => "GOTPC32_TLSDESC",
        R_X86_64_TLSDESC_CALL => "TLSDESC_CALL",
        R_X86_64_TLSDESC => "TLSDESC",
        R_X86_64_IRELATIVE => "IRELATIVE",
        R_X86_64_RELATIVE64 => "RELATIVE64",
        _ => "UNKNOWN_RELA_TYPE",
    }
}

macro_rules! elf_rela_impure_impl { ($from_endian:item) => {

        #[cfg(feature = "std")]
        pub use self::impure::*;

        #[cfg(feature = "std")]
        mod impure {

            use super::*;

            use core::fmt;
            use core::slice;

            use std::fs::File;
            use std::io::{self, Read, Seek};
            use std::io::SeekFrom::Start;

            impl ElfRela for Rela {
                /// Address
                fn r_offset(&self) -> u64 {
                    self.r_offset as u64
                }
                /// Relocation type and symbol index
                fn r_info(&self) -> u64 {
                    self.r_info as u64
                }
                /// Addend
                fn r_addend(&self) -> i64 {
                    self.r_addend as i64
                }
                /// The index into the dynsyms symbol table
                fn r_sym(&self) -> usize {
                    r_sym(self.r_info) as usize
                }
                /// The relocation type
                fn r_typ(&self) -> u64 {
                    r_type(self.r_info) as u64
                }
            }

            impl fmt::Debug for Rela {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    let sym = r_sym(self.r_info);
                    let typ = r_type(self.r_info);
                    write!(f,
                           "r_offset: {:x} {} @ {} r_addend: {:x}",
                           self.r_offset,
                           type_to_str(typ as u64),
                           sym,
                           self.r_addend)
                }
            }

    /// Gets the rela entries given a rela u64 and the _size_ of the rela section in the binary, in bytes.  Works for regular rela and the pltrela table.
    /// Assumes the pointer is valid and can safely return a slice of memory pointing to the relas because:
    /// 1. `rela` points to memory received from the kernel (i.e., it loaded the executable), _or_
    /// 2. The binary has already been mmapped (i.e., it's a `SharedObject`), and hence it's safe to return a slice of that memory.
    /// 3. Or if you obtained the pointer in some other lawful manner
            pub unsafe fn from_raw<'a>(ptr: *const Rela, size: usize) -> &'a [Rela] {
                slice::from_raw_parts(ptr, size / SIZEOF_RELA)
            }

            pub fn from_fd(fd: &mut File, offset: usize, size: usize) -> io::Result<Vec<Rela>> {
                let count = size / SIZEOF_RELA;
                let mut bytes = vec![0u8; size];
                try!(fd.seek(Start(offset as u64)));
                try!(fd.read(&mut bytes));
                let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut Rela, count) };
                let mut res = Vec::with_capacity(count);
                res.extend_from_slice(bytes);
                Ok(res)
            }

            #[cfg(feature = "endian_fd")]
            $from_endian
        }
    };}
