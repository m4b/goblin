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

include!("constants_relocation.rs");

macro_rules! elf_reloc {
    ($size:ident, $isize:ty) => {
        use core::fmt;
        #[repr(C)]
        #[derive(Clone, Copy, PartialEq, Default)]
        #[cfg_attr(feature = "std", derive(Pread, Pwrite, SizeWith))]
        /// Relocation with an explicit addend
        pub struct Rela {
            /// Address
            pub r_offset: $size,
            /// Relocation type and symbol index
            pub r_info: $size,
            /// Addend
            pub r_addend: $isize,
        }
        #[repr(C)]
        #[derive(Clone, PartialEq, Default)]
        #[cfg_attr(feature = "std", derive(Pread, Pwrite, SizeWith))]
        /// Relocation without an addend
        pub struct Rel {
            /// address
            pub r_offset: $size,
            /// relocation type and symbol address
            pub r_info: $size,
        }
        use plain;
        unsafe impl plain::Plain for Rela {}
        unsafe impl plain::Plain for Rel {}

        impl fmt::Debug for Rela {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let sym = r_sym(self.r_info);
                let typ = r_type(self.r_info);
                write!(f,
                       "r_offset: {:x} r_typ: {} r_sym: {} r_addend: {:x}",
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
                       "r_offset: {:x} r_typ: {} r_sym: {}",
                       self.r_offset,
                       typ,
                       sym
                )
            }
        }
    };
}

macro_rules! elf_rela_std_impl { ($size:ident, $isize:ty) => {

        #[cfg(feature = "std")]
        pub use self::std::*;

        #[cfg(feature = "std")]
        mod std {

            use elf::reloc::Reloc;
            use super::*;

            use core::slice;
            use elf::error::*;

            use std::fs::File;
            use std::io::{Read, Seek};
            use std::io::SeekFrom::Start;

            use plain::Methods;

            impl From<Rela> for Reloc {
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

            impl From<Rel> for Reloc {
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

            impl From<Reloc> for Rela {
                fn from(rela: Reloc) -> Self {
                    Rela {
                        r_offset: rela.r_offset as $size,
                        r_info: rela.r_info as $size,
                        r_addend: rela.r_addend as $isize,
                    }
                }
            }

            impl From<Reloc> for Rel {
                fn from(rel: Reloc) -> Self {
                    Rel {
                        r_offset: rel.r_offset as $size,
                        r_info: rel.r_info as $size,
                    }
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

            pub fn from_fd(fd: &mut File, offset: usize, size: usize) -> Result<Vec<Rela>> {
                let count = size / SIZEOF_RELA;
                let mut relocs = vec![Rela::default(); count];
                fd.seek(Start(offset as u64))?;
                fd.read(relocs.as_mut_bytes())?;
                Ok(relocs)
            }
        }
    };
}


pub mod reloc32 {

    pub use elf::reloc::*;

    elf_reloc!(u32, i32);

    pub const SIZEOF_RELA: usize = 4 + 4 + 4;
    pub const SIZEOF_REL: usize = 4 + 4;

    #[inline(always)]
    pub fn r_sym(info: u32) -> u32 {
        info >> 8
    }

    #[inline(always)]
    pub fn r_type(info: u32) -> u32 {
        info & 0xff
    }

    #[inline(always)]
    pub fn r_info(sym: u32, typ: u32) -> u32 {
        (sym << 8) + (typ & 0xff)
    }

    elf_rela_std_impl!(u32, i32);
}


pub mod reloc64 {
    pub use elf::reloc::*;

    elf_reloc!(u64, i64);

    pub const SIZEOF_RELA: usize = 8 + 8 + 8;
    pub const SIZEOF_REL: usize = 8 + 8;

    #[inline(always)]
    pub fn r_sym(info: u64) -> u32 {
        (info >> 32) as u32
    }

    #[inline(always)]
    pub fn r_type(info: u64) -> u32 {
        (info & 0xffffffff) as u32
    }

    #[inline(always)]
    pub fn r_info(sym: u64, typ: u64) -> u64 {
        (sym << 32) + typ
    }

    elf_rela_std_impl!(u64, i64);
}

//////////////////////////////
// Generic Reloc
/////////////////////////////
#[cfg(feature = "std")]
pub use self::std::*;

#[cfg(feature = "std")]
mod std {
    use super::*;
    use core::fmt;
    use core::result;
    use scroll::{self, ctx};
    use container::{Ctx, Container};

    #[derive(Clone, Copy, PartialEq, Default)]
    /// A unified ELF relocation structure
    pub struct Reloc {
        /// Address
        pub r_offset: usize,
        /// Relocation type and symbol index
        pub r_info: usize,
        /// Addend
        pub r_addend: isize,
        /// The index into the corresponding symbol table - either dynamic or regular
        pub r_sym: usize,
        /// The relocation type
        pub r_type: u32,
        /// Whether this was constructed from a rela or rel relocation entry type
        pub is_rela: bool
    }

    impl Reloc {
        pub fn size(is_rela: bool, ctx: Ctx) -> usize {
            use scroll::ctx::SizeWith;
            Reloc::size_with(&(is_rela, ctx))
        }
        #[cfg(feature = "endian_fd")]
        pub fn parse<S: AsRef<[u8]>>(buffer: &S, mut offset: usize, filesz: usize, is_rela: bool, ctx: Ctx) -> ::error::Result<Vec<Reloc>> {
            use scroll::Gread;
            let count = filesz / Reloc::size(is_rela, ctx);
            let mut relocs = Vec::with_capacity(count);
            let mut offset = &mut offset;
            for _ in 0..count {
                let reloc = buffer.gread_with::<Reloc>(offset, (is_rela, ctx))?;
                relocs.push(reloc);
            }
            Ok(relocs)
        }
    }

    type RelocCtx = (bool, Ctx);

    impl ctx::SizeWith<RelocCtx> for Reloc {
        type Units = usize;
        fn size_with( &(is_rela, Ctx { container, .. }): &RelocCtx) -> Self::Units {
            match container {
                Container::Little => {
                    if is_rela { reloc32::SIZEOF_RELA } else { reloc32::SIZEOF_REL }
                },
                Container::Big => {
                    if is_rela { reloc64::SIZEOF_RELA } else { reloc64::SIZEOF_REL }
                }
            }
        }
    }

    impl<'a> ctx::TryFromCtx<'a, (usize, RelocCtx)> for Reloc {
        type Error = scroll::Error;
        fn try_from_ctx(buffer: &'a [u8], (offset, (is_rela, Ctx { container, le })): (usize, RelocCtx)) -> result::Result<Self, Self::Error> {
            use scroll::Pread;
            let reloc = match container {
                Container::Little => {
                    if is_rela {
                        buffer.pread_with::<reloc32::Rela>(offset, le)?.into()
                    } else {
                        buffer.pread_with::<reloc32::Rel>(offset, le)?.into()
                    }
                },
                Container::Big => {
                    if is_rela {
                        buffer.pread_with::<reloc64::Rela>(offset, le)?.into()
                    } else {
                        buffer.pread_with::<reloc64::Rel>(offset, le)?.into()
                    }
                }
            };
            Ok(reloc)
        }
    }

    impl ctx::TryIntoCtx<(usize, Ctx)> for Reloc {
        type Error = scroll::Error;
        /// Writes the relocation into `buffer`; forces `Rel` relocation records for 32-bit containers, and `Rela` for 64-bit containers
        fn try_into_ctx(self, mut buffer: &mut [u8], (offset, Ctx { container, le }): (usize, Ctx)) -> result::Result<(), Self::Error> {
            use scroll::Pwrite;
            match container {
                Container::Little => {
                    let rel: reloc32::Rel = self.into();
                    buffer.pwrite_with(rel, offset, le)?;
                },
                Container::Big => {
                    let rela: reloc64::Rela = self.into();
                    buffer.pwrite_with(rela, offset, le)?;
                },
            };
            Ok(())
        }
    }

    impl fmt::Debug for Reloc {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f,
                   "r_offset: {:x} r_typ: {} r_sym: {} r_addend: {:x} rela: {}",
                   self.r_offset,
                   self.r_type,
                   self.r_sym,
                   self.r_addend,
                   self.is_rela,
            )
        }
    }
}
