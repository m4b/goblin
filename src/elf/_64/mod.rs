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

#[cfg(all(feature = "std", feature = "endian_fd"))]
pub use self::impure::*;

#[cfg(all(feature = "std", feature = "endian_fd"))]
mod impure {

    elf_from!(::std::u64::MAX);

    #[cfg(test)]
    mod tests {
        use std::path::Path;

        #[test]
        fn read_ls() {
            assert!(super::Binary::from_path(Path::new("/bin/ls")).is_ok());
        }
    }
}
