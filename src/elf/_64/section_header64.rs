pub use elf::section_header::*;

elf_section_header!(u64);

pub const SIZEOF_SHDR: usize = 64;

elf_section_header_impure_impl!();
