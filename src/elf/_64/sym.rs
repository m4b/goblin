use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom::Start;
use std::io;
use std::fmt;
use std::slice;

pub use super::super::elf::sym::*;

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
