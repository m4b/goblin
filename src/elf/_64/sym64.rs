pub use elf::sym::*;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "endian_fd", derive(Pread, Pwrite, SizeWith))]
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

elf_sym_impure_impl!(u64);
