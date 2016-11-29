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
#[path="reloc32.rs"]
pub mod reloc;

#[cfg(feature = "std")]
pub use elf::strtab;

#[cfg(feature = "std")]
pub mod gnu_hash {
    elf_gnu_hash_impl!();
}
