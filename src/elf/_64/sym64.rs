pub use elf::sym::*;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default)]
pub struct Sym {
    /// Symbol name (string tbl index)
    pub st_name: u32,
    /// Symbol type and binding
    pub st_info: u8,
    /// Symbol visibility
    pub st_other: u8,
    /// Section index
    pub st_shndx: u16,
    /// Symbol value
    pub st_value: u64,
    /// Symbol size
    pub st_size: u64,
}

pub const SIZEOF_SYM: usize = 4 + 1 + 1 + 2 + 8 + 8;

elf_sym_impure_impl!(
    pub fn parse<S: scroll::Scroll<usize>>(fd: &S, offset: usize, count: usize, little_endian: bool) -> io::Result<Vec<Sym>> {
        let mut syms = Vec::with_capacity(count);
        let mut offset = offset;
        for _ in 0..count {
            let mut sym = Sym::default();
            sym.st_name = try!(fd.read_u32(&mut offset, little_endian));
            sym.st_info = try!(fd.read_u8(&mut offset));
            sym.st_other = try!(fd.read_u8(&mut offset));
            sym.st_shndx = try!(fd.read_u16(&mut offset, little_endian));
            sym.st_value = try!(fd.read_u64(&mut offset, little_endian));
            sym.st_size = try!(fd.read_u64(&mut offset, little_endian));
            syms.push(sym);
        }
        Ok(syms)
    });
