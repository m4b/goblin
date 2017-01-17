pub use elf::section_header::*;

elf_section_header!(u32);

pub const SIZEOF_SHDR: usize = 40;

elf_section_header_impure_impl!();
