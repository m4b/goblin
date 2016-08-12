pub use super::super::header::*;

#[repr(C)]
#[derive(Clone, Default)]
#[cfg_attr(not(feature = "pure"), derive(Debug))]
pub struct Header {
    pub e_ident: [u8; SIZEOF_IDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

pub const SIZEOF_EHDR: usize = 48;
