pub use elf::header::*;

pub const SIZEOF_EHDR: usize = 48;
pub const ELFCLASS: u8 = ELFCLASS32;

elf_header!(u32);
elf_header_impure_impl!(SIZEOF_EHDR);
elf_header_test_peek!(ELFCLASS);
