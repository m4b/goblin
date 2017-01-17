pub use elf::dyn::*;

elf_dyn!(u32);

pub const SIZEOF_DYN: usize = 8;

elf_dyn_impure_impl!(u32);
