pub use elf::dyn::*;

elf_dyn!(u64);

pub const SIZEOF_DYN: usize = 16;

elf_dyn_impure_impl!(u64);
