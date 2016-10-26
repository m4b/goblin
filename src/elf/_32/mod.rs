//! The ELF 32-bit struct definitions and associated values

#[path="header32.rs"]
pub mod header;
#[path="sym32.rs"]
pub mod sym;
#[path="program_header32.rs"]
pub mod program_header;
#[path="section_header32.rs"]
pub mod section_header;
#[path="dyn32.rs"]
pub mod dyn;
#[path="rela32.rs"]
pub mod rela;

#[cfg(feature = "std")]
pub use elf::strtab;
