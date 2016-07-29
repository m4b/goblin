use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom::Start;
use std::io;
use std::fmt;
use std::slice;

pub mod consts {
// sym bindings
pub const STB_LOCAL: u8 = 0; // Local symbol
pub const STB_GLOBAL: u8 = 1; // Global symbol
pub const STB_WEAK: u8 = 2; // Weak symbol
pub const STB_NUM: u8 = 3; // Number of defined types.
pub const STB_LOOS: u8 = 10; // Start of OS-specific
pub const STB_GNU_UNIQUE: u8 = 10; // Unique symbol.
pub const STB_HIOS: u8 = 12; // End of OS-specific
pub const STB_LOPROC: u8 = 13; // Start of processor-specific
pub const STB_HIPROC: u8 = 15; // End of processor-specific
// sym types
pub const STT_NOTYPE: u8 = 0; // Symbol type is unspecified
pub const STT_OBJECT: u8 = 1; // Symbol is a data object
pub const STT_FUNC: u8 = 2; // Symbol is a code object
pub const STT_SECTION: u8 = 3; // Symbol associated with a section
pub const STT_FILE: u8 = 4; // Symbol's name is file name
pub const STT_COMMON: u8 = 5; // Symbol is a common data object
pub const STT_TLS: u8 = 6; // Symbol is thread-local data object
pub const STT_NUM: u8 = 7; // Number of defined types
pub const STT_LOOS: u8 = 10; // Start of OS-specific
pub const STT_GNU_IFUNC: u8 = 10; // Symbol is indirect code object
pub const STT_HIOS: u8 = 12; // End of OS-specific
pub const STT_LOPROC: u8 = 13; // Start of processor-specific
pub const STT_HIPROC: u8 = 15; // End of processor-specific

}

pub use self::consts::*;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default)]
pub struct Sym {
    pub st_name: u32, // Symbol name (string tbl index)
    pub st_info: u8, // Symbol type and binding
    pub st_other: u8, // Symbol visibility
    pub st_shndx: u16, // Section index
    pub st_value: u64, // Symbol value
    pub st_size: u64, // Symbol size
}

pub const SIZEOF_SYM: usize = 4 + 1 + 1 + 2 + 8 + 8;

#[inline(always)]
pub fn st_bind(info: u8) -> u8 {
    info >> 4
}

#[inline(always)]
pub fn st_type(info: u8) -> u8 {
    info & 0xf
}

#[inline(always)]
pub fn is_import(sym: &Sym) -> bool {
    let binding = st_bind(sym.st_info);
    binding == STB_GLOBAL && sym.st_value == 0
}

/// Convenience function to get the &'static str type of this symbol
pub fn get_type(sym: &Sym) -> &'static str {
    type_to_str(st_type(sym.st_info))
}

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

#[cfg(not(feature = "no_endian_fd"))]
pub fn from_fd<'a>(fd: &mut File, offset: usize, count: usize, is_lsb: bool) -> io::Result<Vec<Sym>> {
    use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
    let mut syms = Vec::with_capacity(count);

    try!(fd.seek(Start(offset as u64)));
    for _ in 0..count {
        let mut sym = Sym::default();

        if is_lsb {
            sym.st_name = try!(fd.read_u32::<LittleEndian>());
            sym.st_info = try!(try!(fd.bytes().next().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, ""))));
            sym.st_other = try!(try!(fd.bytes().next().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, ""))));
            sym.st_shndx = try!(fd.read_u16::<LittleEndian>());
            sym.st_value = try!(fd.read_u64::<LittleEndian>());
            sym.st_size = try!(fd.read_u64::<LittleEndian>());
        } else {
            sym.st_name = try!(fd.read_u32::<BigEndian>());
            sym.st_info = try!(try!(fd.bytes().next().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, ""))));
            sym.st_other = try!(try!(fd.bytes().next().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, ""))));
            sym.st_shndx = try!(fd.read_u16::<BigEndian>());
            sym.st_value = try!(fd.read_u64::<BigEndian>());
            sym.st_size = try!(fd.read_u64::<BigEndian>());
        }

        syms.push(sym);
    }

    syms.dedup();
    Ok(syms)
}

#[cfg(feature = "no_endian_fd")]
pub fn from_fd<'a>(fd: &mut File, offset: usize, count: usize, _: bool) -> io::Result<Vec<Sym>> {
    let mut bytes = vec![0u8; count * SIZEOF_SYM]; // afaik this shouldn't work, since i pass in a byte size...
    try!(fd.seek(Start(offset as u64)));
    try!(fd.read(&mut bytes));
    let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut Sym, count) };
    let mut syms = Vec::with_capacity(count);
    syms.extend_from_slice(bytes);
    syms.dedup();
    Ok(syms)
}
