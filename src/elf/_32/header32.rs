pub use elf::header::*;

pub const SIZEOF_EHDR: usize = 52;
pub const ELFCLASS: u8 = ELFCLASS32;

elf_header!(u32);
elf_header_impure_impl!(SIZEOF_EHDR, u32);
elf_header_test!(ELFCLASS);
