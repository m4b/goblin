pub use elf::sym::*;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "endian_fd", derive(Pread, Pwrite))]
pub struct Sym {
    /// Symbol name (string tbl index)
    pub st_name: u32,
    /// Symbol value
    pub st_value: u32,
    /// Symbol size
    pub st_size: u32,
    /// Symbol type and binding
    pub st_info: u8,
    /// Symbol visibility
    pub st_other: u8,
    /// Section index
    pub st_shndx: u16,
}

pub const SIZEOF_SYM: usize = 4 + 1 + 1 + 2 + 4 + 4;

elf_sym_impure_impl!();
