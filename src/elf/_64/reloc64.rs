pub use elf::reloc::*;

elf_reloc!(u64, i64);

pub const SIZEOF_RELA: usize = 8 + 8 + 8;
pub const SIZEOF_REL: usize = 8 + 8;

#[inline(always)]
pub fn r_sym(info: u64) -> u32 {
    (info >> 32) as u32
}

#[inline(always)]
pub fn r_type(info: u64) -> u32 {
    (info & 0xffffffff) as u32
}

#[inline(always)]
pub fn r_info(sym: u64, typ: u64) -> u64 {
    (sym << 32) + typ
}

elf_rela_impure_impl!(u64);
