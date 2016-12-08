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

use core::fmt;

#[derive(Clone, Copy, PartialEq, Default)]
/// A unified ELF relocation structure
pub struct Reloc {
    /// Address
    pub r_offset: usize,
    /// Relocation type and symbol index
    pub r_info: usize,
    /// Addend
    pub r_addend: isize,
    /// The index into the dynsyms symbol table
    pub r_sym: usize,
    /// The relocation type
    pub r_type: u32,
    /// Whether this was constructed from a rela or rel relocation entry type
    pub is_rela: bool
}

#[cfg(feature = "std")]
pub trait ElfReloc {
    /// Address
    fn r_offset(&self) -> u64;
    /// Relocation type and symbol index
    fn r_info(&self) -> u64;
    /// Addend
    fn r_addend(&self) -> i64;
    /// The index into the dynsyms symbol table
    fn r_sym(&self) -> usize;
    /// The relocation type
    fn r_type(&self) -> u32;
}

#[cfg(feature = "std")]
impl ElfReloc for Reloc {
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
        self.r_sym
    }
    /// The relocation type
    fn r_type(&self) -> u32 {
        self.r_type
    }
}

impl fmt::Debug for Reloc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "r_offset: {:x} {} @ {} r_addend: {:x} rela: {}",
               self.r_offset,
               self.r_type,
               self.r_sym,
               self.r_addend,
               self.is_rela,
               )
    }
}

macro_rules! elf_reloc {
    ($size:ident, $typ:ty) => {
    use core::convert::From;
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
    #[repr(C)]
    #[derive(Clone, PartialEq, Default)]
    pub struct Rel {
      /// address
      pub r_offset: $size,
      /// relocation type and symbol address
      pub r_info: $size,
    }

    impl From<Rela> for super::reloc::Reloc {
        fn from(rela: Rela) -> Self {
            Reloc {
                r_offset: rela.r_offset as usize,
                r_info: rela.r_info as usize,
                r_addend: rela.r_addend as isize,
                r_sym: r_sym(rela.r_info) as usize,
                r_type: r_type(rela.r_info),
                is_rela: true,
            }
        }
    }

    impl From<Rel> for super::reloc::Reloc {
        fn from(rel: Rel) -> Self {
            Reloc {
                r_offset: rel.r_offset as usize,
                r_info: rel.r_info as usize,
                r_addend: 0,
                r_sym: r_sym(rel.r_info) as usize,
                r_type: r_type(rel.r_info),
                is_rela: false,
            }
        }
    }

    };
    ($size:ident) => {
      elf_reloc!($size, signed_from_unsigned!($size));
    };
}

macro_rules! signed_from_unsigned {
  (u32) => {i32};
  (u64) => {i64}
}

include!("constants_relocation.rs");

// TODO: parameterize this by architecture
#[inline]
pub fn type_to_str(typ: u32) -> &'static str {
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

macro_rules! elf_rela_impure_impl { ($parse:item) => {

        #[cfg(feature = "std")]
        pub use self::impure::*;

        #[cfg(feature = "std")]
        mod impure {

            use super::*;

            use core::fmt;
            use core::slice;

            use scroll;
            use std::fs::File;
            use std::io::{self, Read, Seek};
            use std::io::SeekFrom::Start;

            impl fmt::Debug for Rela {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    let sym = r_sym(self.r_info);
                    let typ = r_type(self.r_info);
                    write!(f,
                           "r_offset: {:x} {} @ {} r_addend: {:x}",
                           self.r_offset,
                           typ,
                           sym,
                           self.r_addend)
                }
            }

            impl fmt::Debug for Rel {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    let sym = r_sym(self.r_info);
                    let typ = r_type(self.r_info);
                    write!(f,
                           "r_offset: {:x} {} @ {}",
                           self.r_offset,
                           typ,
                           sym
                           )
                }
            }

            impl ElfReloc for Rela {
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
                fn r_type(&self) -> u32 {
                    r_type(self.r_info)
                }
            }

            impl ElfReloc for Rel {
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
                    0
                }
                /// The index into the dynsyms symbol table
                fn r_sym(&self) -> usize {
                    r_sym(self.r_info) as usize
                }
                /// The relocation type
                fn r_type(&self) -> u32 {
                    r_type(self.r_info)
                }
            }

            /// Gets the rela entries given a rela pointer and the _size_ of the rela section in the binary,
            /// in bytes.
            /// Assumes the pointer is valid and can safely return a slice of memory pointing to the relas because:
            /// 1. `ptr` points to memory received from the kernel (i.e., it loaded the executable), _or_
            /// 2. The binary has already been mmapped (i.e., it's a `SharedObject`), and hence it's safe to return a slice of that memory.
            /// 3. Or if you obtained the pointer in some other lawful manner
            pub unsafe fn from_raw_rela<'a>(ptr: *const Rela, size: usize) -> &'a [Rela] {
                slice::from_raw_parts(ptr, size / SIZEOF_RELA)
            }

            /// Gets the rel entries given a rel pointer and the _size_ of the rel section in the binary,
            /// in bytes.
            /// Assumes the pointer is valid and can safely return a slice of memory pointing to the rels because:
            /// 1. `ptr` points to memory received from the kernel (i.e., it loaded the executable), _or_
            /// 2. The binary has already been mmapped (i.e., it's a `SharedObject`), and hence it's safe to return a slice of that memory.
            /// 3. Or if you obtained the pointer in some other lawful manner
            pub unsafe fn from_raw_rel<'a>(ptr: *const Rel, size: usize) -> &'a [Rel] {
                slice::from_raw_parts(ptr, size / SIZEOF_REL)
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
            $parse
        }
    };}
