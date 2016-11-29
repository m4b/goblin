pub use elf::reloc::*;

elf_reloc!(u32);

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

elf_rela_impure_impl!(

    #[cfg(feature = "endian_fd")]
    pub fn parse<R: Read + Seek>(fd: &mut R, offset: usize, size: usize, is_lsb: bool, is_rela: bool) -> io::Result<Vec<Reloc>> {
        use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
        let sizeof_relocation = if is_rela { SIZEOF_RELA } else { SIZEOF_REL };
        let count = size / sizeof_relocation;
        let mut res = Vec::with_capacity(count);

        try!(fd.seek(Start(offset as u64)));
        for _ in 0..count {
            let mut reloc = Reloc::default();
            let info;
            if is_lsb {
                reloc.r_offset = try!(fd.read_u32::<LittleEndian>()) as usize;
                info = try!(fd.read_u32::<LittleEndian>());
                reloc.r_info = info as usize;
                if is_rela { reloc.r_addend = try!(fd.read_i32::<LittleEndian>()) as isize; }
            } else {
                reloc.r_offset = try!(fd.read_u32::<BigEndian>()) as usize;
                info = try!(fd.read_u32::<BigEndian>());
                reloc.r_info = info as usize;
                if is_rela { reloc.r_addend = try!(fd.read_i32::<BigEndian>()) as isize; }
            }
            reloc.r_sym = r_sym(info) as usize;
            reloc.r_type = r_type(info) as u32;
            reloc.is_rela = is_rela;
            res.push(reloc);
        }
        Ok(res)
    }
);
