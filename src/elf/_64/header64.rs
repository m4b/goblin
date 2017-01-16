pub use elf::header::*;

pub const SIZEOF_EHDR: usize = 64;
pub const ELFCLASS: u8 = ELFCLASS64;

elf_header!(u64);
elf_header_impure_impl!(SIZEOF_EHDR);
elf_header_test!(ELFCLASS);
