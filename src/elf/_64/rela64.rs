pub use elf::rela::*;

elf_rela!(u64, i64);

pub const SIZEOF_RELA: usize = 8 + 8 + 8;

#[inline(always)]
pub fn r_sym(info: u64) -> u64 {
    info >> 32
}

#[inline(always)]
pub fn r_type(info: u64) -> u64 {
    info & 0xffffffff
}

#[inline(always)]
pub fn r_info(sym: u64, typ: u64) -> u64 {
    (sym << 32) + typ
}

elf_rela_impure_impl!(
    pub fn parse<R: Read + Seek>(fd: &mut R, offset: usize, size: usize, is_lsb: bool) -> io::Result<Vec<Rela>> {
        use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
        let count = size / SIZEOF_RELA;
        let mut res = Vec::with_capacity(count);

        try!(fd.seek(Start(offset as u64)));
        for _ in 0..count {
            let mut rela = Rela::default();

            if is_lsb {
                rela.r_offset = try!(fd.read_u64::<LittleEndian>());
                rela.r_info = try!(fd.read_u64::<LittleEndian>());
                rela.r_addend = try!(fd.read_i64::<LittleEndian>());
            } else {
                rela.r_offset = try!(fd.read_u64::<BigEndian>());
                rela.r_info = try!(fd.read_u64::<BigEndian>());
                rela.r_addend = try!(fd.read_i64::<BigEndian>());
            }

            res.push(rela);
        }

        res.dedup();
        Ok(res)
    });
