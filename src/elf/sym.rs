#[cfg(feature = "std")]
pub trait ElfSym {
    fn st_name(&self) -> usize;
    fn st_info(&self) -> u8;
    fn st_other(&self) -> u8;
    fn st_shndx(&self) -> usize;
    fn st_value(&self) -> u64;
    fn st_size(&self) -> u64;
    fn is_function(&self) -> bool;
    fn is_import(&self) -> bool;
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

/// Get the ST binding.
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
    let binding = st_bind(info);
    binding == STB_GLOBAL && value == 0
}

/// Convenience function to get the &'static str type from the symbols `st_info`.
pub fn get_type(info: u8) -> &'static str {
    type_to_str(st_type(info))
}

/// Get the string for some binding.
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
        ($from_endian:item) => {

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

                impl ElfSym for Sym {
                    fn st_name(&self) -> usize {
                        self.st_name as usize
                    }
                    fn st_info(&self) -> u8 {
                        self.st_info
                    }
                    fn st_other(&self) -> u8 {
                        self.st_other
                    }
                    fn st_shndx(&self) -> usize {
                        self.st_shndx as usize
                    }
                    fn st_value(&self) -> u64 {
                        self.st_value as u64
                    }
                    fn st_size(&self) -> u64 {
                        self.st_size as u64
                    }
                    fn is_function(&self) -> bool {
                        self.is_function()
                    }
                    fn is_import(&self) -> bool {
                        self.is_import()
                    }
                }

                impl Sym {
                   /// Checks whether this `Sym` has `STB_GLOBAL`/`STB_WEAK` binding and a `st_value` of 0
                   pub fn is_import(&self) -> bool {
                     let binding = self.st_info >> 4;
                     (binding == STB_GLOBAL || binding == STB_WEAK) && self.st_value == 0
                   }
                   /// Checks whether this `Sym` has type `STT_FUNC`
                   pub fn is_function(&self) -> bool {
                     st_type(self.st_info) == STT_FUNC
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

                pub fn from_fd<'a>(fd: &mut File, offset: usize, count: usize) -> io::Result<Vec<Sym>> {
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
                $from_endian

            }
        };
    }
