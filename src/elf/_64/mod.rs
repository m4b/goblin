//! The ELF 64-bit struct definitions and associated values

#[path="header64.rs"]
pub mod header;
#[path="sym64.rs"]
pub mod sym;
#[path="program_header64.rs"]
pub mod program_header;
#[path="section_header64.rs"]
pub mod section_header;
#[path="dyn64.rs"]
pub mod dyn;
#[path="rela64.rs"]
pub mod rela;

#[cfg(feature = "std")]
pub mod gnu_hash;

#[cfg(feature = "std")]
pub use elf::strtab;
