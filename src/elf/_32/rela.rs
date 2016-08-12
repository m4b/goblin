pub use super::super::rela::*;

// Stupid 32 bit binaries have Rel too, because 4 extra bytes for every relocation for an addend of 0 was prohibitive back in 1906.
// I think 32-bit binaries are stupid relics from the past in case that wasn't clear
#[repr(C)]
#[derive(Clone, PartialEq, Default)]
#[cfg_attr(not(feature = "pure"), derive(Debug))]
pub struct Rel {
    r_offset: u32, // address
    r_info: u32, // relocation type and symbol address
}

#[repr(C)]
#[derive(Clone, PartialEq, Default)]
#[cfg_attr(not(feature = "pure"), derive(Debug))]
pub struct Rela {
    pub r_offset: u32, // Address
    pub r_info: u32, // Relocation type and symbol index
    pub r_addend: i32, // Addend
}

pub const SIZEOF_RELA: usize = 4 + 4 + 4;

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
