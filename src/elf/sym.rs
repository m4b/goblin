use core::fmt;
use scroll::{self, ctx, Pread};
use error;
use core::result;
use container::{Ctx, Container};

#[cfg(feature = "std")]
#[derive(Default, PartialEq, Clone)]
pub struct ElfSym {
    pub st_name:     usize,
    pub st_info:     u8,
    pub st_other:    u8,
    pub st_shndx:    usize,
    pub st_value:    u64,
    pub st_size:     u64,
}

impl ElfSym {
    pub fn size(container: Container) -> usize {
        match container {
            Container::Little => {
                super::super::elf32::sym::SIZEOF_SYM
            },
            Container::Big => {
                super::super::elf64::sym::SIZEOF_SYM
            },
        }
    }
    /// Checks whether this `Sym` has `STB_GLOBAL`/`STB_WEAK` bind and a `st_value` of 0
    pub fn is_import(&self) -> bool {
        let bind = self.st_bind();
        (bind == STB_GLOBAL || bind == STB_WEAK) && self.st_value == 0
    }
    /// Checks whether this `Sym` has type `STT_FUNC`
    pub fn is_function(&self) -> bool {
        st_type(self.st_info) == STT_FUNC
    }
    /// Get the ST bind.
    ///
    /// This is the first four bits of the byte.
    #[inline]
    pub fn st_bind(&self) -> u8 {
        self.st_info >> 4
    }
    /// Get the ST type.
    ///
    /// This is the last four bits of the byte.
    #[inline]
    pub fn st_type(&self) -> u8 {
        self.st_info & 0xf
    }
    #[cfg(feature = "endian_fd")]
    /// Parse `count` vector of ELF symbols from `offset`
    pub fn parse<S: AsRef<[u8]>>(bytes: &S, mut offset: usize, count: usize, ctx: Ctx) -> error::Result<Vec<ElfSym>> {
        let mut syms = Vec::with_capacity(count);
        let size = Self::size(ctx.container);
        for _ in 0..count {
            let sym = bytes.pread_with(offset, ctx)?;
            offset += size;
            syms.push(sym);
        }
        Ok(syms)
    }
}

impl fmt::Debug for ElfSym {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bind = self.st_bind();
        let typ = self.st_type();
        write!(f,
               "st_name: {} {} {} st_other: {} st_shndx: {} st_value: {:x} st_size: {}",
               self.st_name,
               bind_to_str(bind),
               type_to_str(typ),
               self.st_other,
               self.st_shndx,
               self.st_value,
               self.st_size)
    }
}

impl<'a> ctx::TryFromCtx<'a, (usize, Ctx)> for ElfSym {
    type Error = scroll::Error;
    fn try_from_ctx(buffer: &'a [u8], (offset, Ctx { container, le}): (usize, Ctx)) -> result::Result<Self, Self::Error> {
        use scroll::Pread;
        let sym = match container {
            Container::Little => {
                buffer.pread_with::<super::super::elf32::sym::Sym>(offset, le)?.into()
            },
            Container::Big => {
                buffer.pread_with::<super::super::elf64::sym::Sym>(offset, le)?.into()
            }
        };
        Ok(sym)
    }
}

impl ctx::TryIntoCtx<(usize, Ctx)> for ElfSym {
    type Error = scroll::Error;
    fn try_into_ctx(self, mut buffer: &mut [u8], (offset, Ctx {container, le}): (usize, Ctx)) -> result::Result<(), Self::Error> {
        use scroll::Pwrite;
        match container {
            Container::Little => {
                let sym: super::super::elf32::sym::Sym = self.into();
                buffer.pwrite_with(sym, offset, le)?;
            },
            Container::Big => {
                let sym: super::super::elf64::sym::Sym = self.into();
                buffer.pwrite_with(sym, offset, le)?;
            }
        }
        Ok(())
    }
}

/// === Sym bindings ===
/// Local symbol.
pub const STB_LOCAL: u8 = 0;
/// Global symbol.
pub const STB_GLOBAL: u8 = 1;
/// Weak symbol.
pub const STB_WEAK: u8 = 2;
/// Number of defined types..
pub const STB_NUM: u8 = 3;
/// Start of OS-specific.
pub const STB_LOOS: u8 = 10;
/// Unique symbol..
pub const STB_GNU_UNIQUE: u8 = 10;
/// End of OS-specific.
pub const STB_HIOS: u8 = 12;
/// Start of processor-specific.
pub const STB_LOPROC: u8 = 13;
/// End of processor-specific.
pub const STB_HIPROC: u8 = 15;

/// === Sym types ===
/// Symbol type is unspecified.
pub const STT_NOTYPE: u8 = 0;
/// Symbol is a data object.
pub const STT_OBJECT: u8 = 1;
/// Symbol is a code object.
pub const STT_FUNC: u8 = 2;
/// Symbol associated with a section.
pub const STT_SECTION: u8 = 3;
/// Symbol's name is file name.
pub const STT_FILE: u8 = 4;
/// Symbol is a common data object.
pub const STT_COMMON: u8 = 5;
/// Symbol is thread-local data object.
pub const STT_TLS: u8 = 6;
/// Number of defined types.
pub const STT_NUM: u8 = 7;
/// Start of OS-specific.
pub const STT_LOOS: u8 = 10;
/// Symbol is indirect code object.
pub const STT_GNU_IFUNC: u8 = 10;
/// End of OS-specific.
pub const STT_HIOS: u8 = 12;
/// Start of processor-specific.
pub const STT_LOPROC: u8 = 13;
/// End of processor-specific.
pub const STT_HIPROC: u8 = 15;

/// Get the ST bind.
///
/// This is the first four bits of the byte.
#[inline]
pub fn st_bind(info: u8) -> u8 {
    info >> 4
}

/// Get the ST type.
///
/// This is the last four bits of the byte.
#[inline]
pub fn st_type(info: u8) -> u8 {
    info & 0xf
}

/// Is this information defining an import?
#[inline]
pub fn is_import(info: u8, value: u64) -> bool {
    let bind = st_bind(info);
    bind == STB_GLOBAL && value == 0
}

/// Convenience function to get the &'static str type from the symbols `st_info`.
pub fn get_type(info: u8) -> &'static str {
    type_to_str(st_type(info))
}

/// Get the string for some bind.
#[inline]
pub fn bind_to_str(typ: u8) -> &'static str {
    match typ {
        STB_LOCAL => "LOCAL",
        STB_GLOBAL => "GLOBAL",
        STB_WEAK => "WEAK",
        STB_NUM => "NUM",
        STB_GNU_UNIQUE => "GNU_UNIQUE",
        _ => "UNKNOWN_STB",
    }
}

/// Get the string for some type.
#[inline]
pub fn type_to_str(typ: u8) -> &'static str {
    match typ {
        STT_NOTYPE => "NOTYPE",
        STT_OBJECT => "OBJECT",
        STT_FUNC => "FUNC",
        STT_SECTION => "SECTION",
        STT_FILE => "FILE",
        STT_COMMON => "COMMON",
        STT_TLS => "TLS",
        STT_NUM => "NUM",
        STT_GNU_IFUNC => "GNU_IFUNC",
        _ => "UNKNOWN_STT",
    }
}

macro_rules! elf_sym_impure_impl {
    ($size:ty) => {

        #[cfg(feature = "std")]
        pub use self::impure::*;

        #[cfg(feature = "std")]
        mod impure {
            use super::*;
            use elf::error::*;

            use core::fmt;
            use core::slice;

            use scroll;
            use std::fs::File;
            use std::io::{Read, Seek};
            use std::io::SeekFrom::Start;

            impl Sym {
                /// Checks whether this `Sym` has `STB_GLOBAL`/`STB_WEAK` bind and a `st_value` of 0
                pub fn is_import(&self) -> bool {
                    let bind = self.st_info >> 4;
                    (bind == STB_GLOBAL || bind == STB_WEAK) && self.st_value == 0
                }
                /// Checks whether this `Sym` has type `STT_FUNC`
                pub fn is_function(&self) -> bool {
                    st_type(self.st_info) == STT_FUNC
                }
            }

            impl From<Sym> for ElfSym {
                fn from(sym: Sym) -> Self {
                    ElfSym {
                        st_name:     sym.st_name as usize,
                        st_info:     sym.st_info,
                        st_other:    sym.st_other,
                        st_shndx:    sym.st_shndx as usize,
                        st_value:    sym.st_value as u64,
                        st_size:     sym.st_size as u64,
                    }
                }
            }

            impl From<ElfSym> for Sym {
                fn from(sym: ElfSym) -> Self {
                    Sym {
                        st_name:     sym.st_name as u32,
                        st_info:     sym.st_info,
                        st_other:    sym.st_other,
                        st_shndx:    sym.st_shndx as u16,
                        st_value:    sym.st_value as $size,
                        st_size:     sym.st_size as $size,
                    }
                }
            }

            impl fmt::Debug for Sym {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    let bind = st_bind(self.st_info);
                    let typ = st_type(self.st_info);
                    write!(f,
                           "st_name: {} {} {} st_other: {} st_shndx: {} st_value: {:x} st_size: {}",
                           self.st_name,
                           bind_to_str(bind),
                           type_to_str(typ),
                           self.st_other,
                           self.st_shndx,
                           self.st_value,
                           self.st_size)
                }
            }

            pub unsafe fn from_raw<'a>(symp: *const Sym, count: usize) -> &'a [Sym] {
                slice::from_raw_parts(symp, count)
            }

            pub fn from_fd<'a>(fd: &mut File, offset: usize, count: usize) -> Result<Vec<Sym>> {
                // TODO: AFAIK this shouldn't work, since i pass in a byte size...
                // FIX THIS, unecessary allocations + unsafety here
                let mut bytes = vec![0u8; count * SIZEOF_SYM];
                try!(fd.seek(Start(offset as u64)));
                try!(fd.read(&mut bytes));
                let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut Sym, count) };
                let mut syms = Vec::with_capacity(count);
                syms.extend_from_slice(bytes);
                syms.dedup();
                Ok(syms)
            }

            #[cfg(feature = "endian_fd")]
            pub fn parse<S: scroll::Gread>(bytes: &S, mut offset: usize, count: usize, endianness: scroll::Endian) -> Result<Vec<Sym>> {
                let mut syms = Vec::with_capacity(count);
                let mut offset = &mut offset;
                for _ in 0..count {
                    let sym = bytes.gread_with(offset, endianness)?;
                    syms.push(sym);
                }
                Ok(syms)
            }
        }
    };
}
