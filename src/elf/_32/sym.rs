pub use super::super::elf::sym::*;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default)]
pub struct Sym {
    pub st_name: u32, // Symbol name (string tbl index)
    pub st_value: u32, // Symbol value
    pub st_size: u32, // Symbol size
    pub st_info: u8, // Symbol type and binding
    pub st_other: u8, // Symbol visibility
    pub st_shndx: u16, // Section index
}

pub const SIZEOF_SYM: usize = 4 + 1 + 1 + 2 + 4 + 4;

elf_sym_impure_impl!(
    pub fn from_fd<'a>(fd: &mut File, offset: usize, count: usize, is_lsb: bool) -> io::Result<Vec<Sym>> {
        use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
        let mut syms = Vec::with_capacity(count);

        try!(fd.seek(Start(offset as u64)));
        for _ in 0..count {
            let mut sym = Sym::default();

            if is_lsb {
                sym.st_name = try!(fd.read_u32::<LittleEndian>());
                sym.st_value = try!(fd.read_u32::<LittleEndian>());
                sym.st_size = try!(fd.read_u32::<LittleEndian>());
                sym.st_info = try!(try!(fd.bytes().next().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, ""))));
                sym.st_other = try!(try!(fd.bytes().next().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, ""))));
                sym.st_shndx = try!(fd.read_u16::<LittleEndian>());
            } else {
                sym.st_name = try!(fd.read_u32::<BigEndian>());
                sym.st_value = try!(fd.read_u32::<BigEndian>());
                sym.st_size = try!(fd.read_u32::<BigEndian>());
                sym.st_info = try!(try!(fd.bytes().next().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, ""))));
                sym.st_other = try!(try!(fd.bytes().next().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, ""))));
                sym.st_shndx = try!(fd.read_u16::<BigEndian>());
            }
            syms.push(sym);
        }

        syms.dedup();
        Ok(syms)
    });
