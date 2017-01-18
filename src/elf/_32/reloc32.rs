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

elf_rela_impure_impl!(u32);
