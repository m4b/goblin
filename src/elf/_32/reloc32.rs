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
    pub fn parse<S: scroll::Gread>(fd: &S, offset: usize, size: usize, little_endian: scroll::Endian, is_rela: bool) -> Result<Vec<Reloc>> {
        let sizeof_relocation = if is_rela { SIZEOF_RELA } else { SIZEOF_REL };
        let count = size / sizeof_relocation;
        let mut res = Vec::with_capacity(count);
        let mut offset = offset;
        for _ in 0..count {
            let mut reloc = Reloc::default();
            reloc.r_offset = fd.gread::<u32>(&mut offset, little_endian)? as usize;
            let info = fd.gread::<u32>(&mut offset, little_endian)?;
            reloc.r_info = info as usize;
            if is_rela { reloc.r_addend = fd.gread::<i32>(&mut offset, little_endian)? as isize; }
            reloc.r_sym = r_sym(info) as usize;
            reloc.r_type = r_type(info) as u32;
            reloc.is_rela = is_rela;
            res.push(reloc);
        }
        Ok(res)
    }
);
