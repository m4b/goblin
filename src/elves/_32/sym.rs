pub use super::super::sym::*;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default)]
#[derive(Debug)]
pub struct Sym {
    pub st_name: u32, // Symbol name (string tbl index)
    pub st_value: u32, // Symbol value
    pub st_size: u32, // Symbol size
    pub st_info: u8, // Symbol type and binding
    pub st_other: u8, // Symbol visibility
    pub st_shndx: u16, // Section index
}

pub const SIZEOF_SYM: usize = 4 + 1 + 1 + 2 + 4 + 4;
