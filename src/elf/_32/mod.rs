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
    pub use super::super::elf::strtab;

    use super::{header, program_header, dyn, sym, rela};

    #[derive(Debug)]
    pub struct Binary {
        pub header: header::Header,
        pub program_headers: Vec<program_header::ProgramHeader>,
        pub dynamic: Option<Vec<dyn::Dyn>>,
        pub symtab: Vec<sym::Sym>,
        pub rela: Vec<rela::Rela>,
        pub pltrela: Vec<rela::Rela>,
        pub strtab: Vec<String>,
        pub soname: Option<String>,
        pub interpreter: Option<String>,
        pub libraries: Vec<String>,
        pub is_lib: bool,
        pub size: usize,
        pub entry: usize,
    }
}
