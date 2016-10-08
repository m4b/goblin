//! The ELF 64-bit struct definitions and associated values

pub mod header;
pub mod program_header;
pub mod section_header;
pub mod dyn;
pub mod rela;
pub mod sym;

#[cfg(not(feature = "pure"))]
pub mod gnu_hash;

#[cfg(not(feature = "pure"))]
pub use self::impure::*;

#[cfg(not(feature = "pure"))]
mod impure {

    elf_from_fd!(::std::u64::MAX);

    #[cfg(test)]
    mod tests {
        use std::path::Path;

        #[test]
        fn read_ls() {
            assert!(super::Binary::from_path(Path::new("/bin/ls")).is_ok());
        }
    }
}
