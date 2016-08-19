//! The ELF 32-bit struct definitions and associated values

pub mod header;
pub mod sym;
pub mod program_header;
pub mod section_header;
pub mod dyn;
pub mod rela;

#[cfg(not(feature = "pure"))]
pub use self::impure::*;

#[cfg(not(feature = "pure"))]
mod impure {
    elf_from_fd!(::std::u32::MAX);
}
