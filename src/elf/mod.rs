//! The generic ELF module, which gives access to ELF constants and other helper functions, which are independent of ELF bithood.  Also defines an `Elf` struct which implements a unified parser that returns a wrapped `Elf64` or `Elf32` binary.
//!
//! To access the fields of the contents of the binary (i.e., `ph.p_type`),
//! instead of directly getting the struct fields, you call the similarly named methods.
//!
//! # Example
//!
//! ```rust, no_run
//! use std::fs::File;
//!
//! pub fn read (fd: &mut File) {
//!   match goblin::elf::Elf::parse(fd) {
//!     Ok(binary) => {
//!       let entry = binary.entry;
//!       for ph in binary.program_headers {
//!         if ph.p_type() == goblin::elf::program_header::PT_LOAD {
//!           let mut _buf = vec![0u8; ph.p_filesz() as usize];
//!           // read responsibly
//!          }
//!       }
//!     },
//!     Err(_) => ()
//!   }
//! }
//! ```
//!
//! This will properly access the underlying 32-bit or 64-bit binary automatically. Note that since
//! 32-bit binaries typically have shorter 32-bit values in some cases (specifically for addresses and pointer
//! values), these values are upcasted to u64/i64s when appropriate.
//!
//! See [goblin::elf::Elf](struct.Elf.html) for more information.
//!
//! You are still free to use the specific 32-bit or 64-bit versions by accessing them through `goblin::elf64`, etc., but you will have to parse and/or construct the various components yourself.
//! In other words, there is no 32/64-bit `Elf` struct, only the unified version.
//!
//! # Note
//! To use the automagic ELF datatype union parser, you _must_ enable/opt-in to the  `elf64`, `elf32`, and
//! `endian_fd` features if you disable `default`.

#[cfg(feature = "std")]
pub mod strtab;

// These are shareable values for the 32/64 bit implementations.
//
// They are publicly re-exported by the pub-using module
#[macro_use]
pub mod header;
#[macro_use]
pub mod program_header;
#[macro_use]
pub mod section_header;
#[macro_use]
pub mod sym;
#[macro_use]
pub mod dyn;
#[macro_use]
pub mod rela;

#[cfg(all(feature = "std", feature = "elf32", feature = "elf64", feature = "endian_fd"))]
pub use self::impure::*;

#[cfg(all(feature = "std", feature = "elf32", feature = "elf64", feature = "endian_fd"))]
#[macro_use]
mod impure {
    use std::io::{self, Read, Seek, Cursor};
    use std::io::SeekFrom::Start;
    use std::fs::File;
    use std::path::Path;
    use std::ops::{Deref};

    use super::header;
    use super::strtab::Strtab;

    use elf32;
    use elf64;

    #[derive(Debug, Clone, PartialEq, Eq)]
    /// Simple union wrapper for 32/64 bit versions of the structs. Really just the `Either`
    /// enum. Each wrapped elf object (Sym, Dyn) implements a deref coercion into the
    /// generic trait for that object, hence you access the fields via methods instead
    /// of direct field access. You shouldn't need to really worry about this enum though.
    pub enum Unified<T32, T64> {
        Elf32(T32),
        Elf64(T64),
    }

    macro_rules! impl_deref {
        () => {
            fn deref(&self) -> &Self::Target {
                match *self {
                    Unified::Elf32(ref thing) => {
                        thing
                    },
                    Unified::Elf64(ref thing) => {
                        thing
                    }
                }
            }
        }
    }

    macro_rules! wrap {
        (elf32, $item:ident) => {
                 Unified::Elf32($item)
        };
        (elf64, $item:ident) => {
                 Unified::Elf64($item)
        }
    }

    #[derive(Debug, Clone)]
    /// A Union wrapper for a vector or list of wrapped ELF objects.
    /// Lazily converts its contents to a wrapped version during iteration.
    pub struct ElfVec<T32, T64> {
        count: usize,
        contents: Unified<Vec<T32>, Vec<T64>>
    }

    impl<T32, T64> ElfVec<T32, T64> where T32: Clone, T64: Clone {
        pub fn new (contents: Unified<Vec<T32>, Vec<T64>>) -> ElfVec<T32, T64> {
            let count = match contents {
                Unified::Elf32(ref vec) => vec.len(),
                Unified::Elf64(ref vec) => vec.len(),
            };
            ElfVec{
                count: count,
                contents: contents
            }
        }
        pub fn len (&self) -> usize {
            self.count
        }

        pub fn get (&self, _index: usize) -> Unified<T32, T64> {
            match self.contents {
                Unified::Elf32(ref vec) => Unified::Elf32(vec[_index].clone()),
                Unified::Elf64(ref vec) => Unified::Elf64(vec[_index].clone()),
            }
        }
    }

    #[derive(Debug, Clone)]
    /// Simple iterator implementation. Lazily converts underlying vector stream to
    /// wrapped version. Currently clones the element because I'm also lazy.
    pub struct ElfVecIter<T32, T64> {
        current: usize,
        contents: Unified<Vec<T32>, Vec<T64>>,
        end: usize,
    }

    impl<T32, T64> Iterator for ElfVecIter<T32, T64> where T32: Clone, T64: Clone {
        type Item = Unified<T32, T64>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.current >= self.end {
                None
            } else {
                let res = match self.contents {
                    Unified::Elf32(ref vec) => Unified::Elf32(vec[self.current].clone()),
                    Unified::Elf64(ref vec) => Unified::Elf64(vec[self.current].clone()),
                };
                self.current += 1;
                Some(res)
            }
        }
    }

    #[derive(Debug, Clone)]
    /// A hack so you can borrow the iterator instead of taking ownership if you don't want to.
    /// Doesn't work very well, need more robust solution.
    pub struct ElfVecIterBorrow<'a, T32:'a, T64:'a> {
        current: usize,
        contents: &'a Unified<Vec<T32>, Vec<T64>>,
        end: usize,
    }

    impl<'a, T32:'a, T64:'a> Iterator for ElfVecIterBorrow<'a, T32, T64> where T32: Clone, T64: Clone {
        type Item = Unified<T32, T64>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.current == self.end {
                None
            } else {
                let res = match self.contents {
                    &Unified::Elf32(ref vec) => Unified::Elf32(vec[self.current].clone()),
                    &Unified::Elf64(ref vec) => Unified::Elf64(vec[self.current].clone()),
                };
                self.current += 1;
                Some(res)
            }
        }
    }

    impl<'a, T32, T64> IntoIterator for &'a ElfVec<T32, T64> where T32: Clone, T64: Clone {
        type Item = Unified<T32, T64>;
        type IntoIter = ElfVecIterBorrow<'a, T32, T64>;

        fn into_iter(self) -> Self::IntoIter {
            ElfVecIterBorrow {
                current: 0,
                end: self.count,
                contents: &self.contents,
            }
        }
    }

    impl<T32, T64> IntoIterator for ElfVec<T32, T64> where T32: Clone, T64: Clone {
        type Item = Unified<T32, T64>;
        type IntoIter = ElfVecIter<T32, T64>;

        fn into_iter(self) -> Self::IntoIter {
            ElfVecIter {
                current: 0,
                end: self.count,
                contents: self.contents,
            }
        }
    }

    macro_rules! elf_list {
        ($class:ident, $collection:ident) => {
            ElfVec::new(wrap!($class, $collection))
        }
    }

    pub type Header = Unified<elf32::header::Header, elf64::header::Header>;
    pub type ProgramHeader = Unified<elf32::program_header::ProgramHeader, elf64::program_header::ProgramHeader>;
    pub type SectionHeader = Unified<elf32::section_header::SectionHeader, elf64::section_header::SectionHeader>;
    pub type Rela = Unified<elf32::rela::Rela, elf64::rela::Rela>;
    pub type Sym = Unified<elf32::sym::Sym, elf64::sym::Sym>;
    pub type Dyn = Unified<elf32::dyn::Dyn, elf64::dyn::Dyn>;

    impl Deref for Header {
        type Target = super::header::ElfHeader;
        impl_deref!();
    }
    impl Deref for ProgramHeader {
        type Target = super::program_header::ElfProgramHeader;
        impl_deref!();
    }
    impl Deref for SectionHeader {
        type Target = super::section_header::ElfSectionHeader;
        impl_deref!();
    }
    impl Deref for Rela {
        type Target = super::rela::ElfRela;
        impl_deref!();
    }
    impl Deref for Sym {
        type Target = super::sym::ElfSym;
        impl_deref!();
    }
    impl Deref for Dyn {
        type Target = super::dyn::ElfDyn;
        impl_deref!();
    }

    pub type ProgramHeaders = ElfVec<elf32::program_header::ProgramHeader, elf64::program_header::ProgramHeader>;
    pub type SectionHeaders = ElfVec<elf32::section_header::SectionHeader, elf64::section_header::SectionHeader>;
    pub type Syms = ElfVec<elf32::sym::Sym, elf64::sym::Sym>;
    pub type Dynamic = ElfVec<elf32::dyn::Dyn, elf64::dyn::Dyn>;
    pub type Relas = ElfVec<elf32::rela::Rela, elf64::rela::Rela>;

    #[derive(Debug)]
    /// A "Unified" ELF binary. Contains either 32-bit or 64-bit underlying structs.
    /// To access the fields of the underlying struct, call the field name as a method,
    /// e.g., `dyn.d_val()`
    pub struct Elf {
        /// The ELF header, which provides a rudimentary index into the rest of the binary
        pub header: Header,
        /// The program headers; they primarily tell the kernel and the dynamic linker
        /// how to load this binary
        pub program_headers: ProgramHeaders,
        /// The sections headers. These are strippable, never count on them being
        /// here unless you're a static linker!
        pub section_headers: SectionHeaders,
        /// The section header string table
        pub shdr_strtab: Strtab<'static>,
        /// The string table for the dynamically accessible symbols
        pub dynstrtab: Strtab<'static>,
        /// The dynamically accessible symbols, i.e., exports, imports.
        /// This is what the dynamic linker uses to dynamically load and link your binary,
        /// or find imported symbols for binaries which dynamically link against your library
        pub dynsyms: Syms,
        /// The debugging symbol array
        pub syms: Syms,
        /// The string table for the symbol array
        pub strtab: Strtab<'static>,
        /// The _DYNAMIC array
        pub dynamic: Option<Dynamic>,
        /// The regular relocation entries (strings, copy-data, etc.)
        pub rela: Relas,
        /// The plt relocation entries (procedure linkage table)
        pub pltrela: Relas,
        /// The binary's soname, if it has one
        pub soname: Option<String>,
        /// The binary's program interpreter (e.g., dynamic linker), if it has one
        pub interpreter: Option<String>,
        /// A list of this binary's dynamic libraries it uses, if there are any
        pub libraries: Vec<String>,
        pub is_64: bool,
        /// Whether this is a shared object or not
        pub is_lib: bool,
        /// The binaries entry point address, if it has one
        pub entry: u64,
        /// The bias used to overflow virtual memory addresses into physical byte offsets into the binary
        pub bias: u64,
        /// Whether the binary is little endian or not
        pub little_endian: bool,
    }

    macro_rules! wrap_dyn {
      ($class:ident, $dynamic:ident) => {{
            if let Some(dynamic) = $dynamic {
                Some (elf_list!($class, dynamic))
            } else {
                None
            }
      }}
    }
    macro_rules! intmax {
      (elf32) => {
        !0
      };
      (elf64) => {
        ::core::u64::MAX
      }
    }

    macro_rules! parse_impl {
    ($class:ident, $fd:ident) => {{
        let header = try!($class::header::Header::parse($fd));
        let entry = header.e_entry as usize;
        let is_lib = header.e_type == $class::header::ET_DYN;
        let is_lsb = header.e_ident[$class::header::EI_DATA] == $class::header::ELFDATA2LSB;
        let is_64 = header.e_ident[$class::header::EI_CLASS] == $class::header::ELFCLASS64;

        let program_headers = try!($class::program_header::ProgramHeader::parse($fd, header.e_phoff as u64, header.e_phnum as usize, is_lsb));

        let dynamic = try!($class::dyn::parse($fd, &program_headers, is_lsb));
        let mut bias: usize = 0;
        for ph in &program_headers {
            if ph.p_type == $class::program_header::PT_LOAD {
                // this is an overflow hack that allows us to use virtual memory addresses
                // as though they're in the file by generating a fake load bias which is then
                // used to overflow the values in the dynamic array, and in a few other places
                // (see Dyn::DynamicInfo), to generate actual file offsets; you may have to
                // marinate a bit on why this works. i am unsure whether it works in every
                // conceivable case. i learned this trick from reading too much dynamic linker
                // C code (a whole other class of C code) and having to deal with broken older
                // kernels on VMs. enjoi
                bias = ((intmax!($class) - ph.p_vaddr).wrapping_add(1)) as usize;
                break;
            }
        }

        let mut interpreter = None;
        for ph in &program_headers {
            if ph.p_type == $class::program_header::PT_INTERP {
                let mut bytes = vec![0u8; (ph.p_filesz - 1) as usize];
                try!($fd.seek(Start(ph.p_offset as u64)));
                try!($fd.read(&mut bytes));
                interpreter = Some(String::from_utf8(bytes).unwrap())
            }
        }

        let section_headers = try!($class::section_header::SectionHeader::parse($fd, header.e_shoff as u64, header.e_shnum as usize, is_lsb));

        let mut syms = vec![];
        let mut strtab = $class::strtab::Strtab::default();
        for shdr in &section_headers {
            if shdr.sh_type as u32 == $class::section_header::SHT_SYMTAB {
                let count = shdr.sh_size / shdr.sh_entsize;
                syms = try!($class::sym::parse($fd, shdr.sh_offset as usize, count as usize, is_lsb))
            }
            if shdr.sh_type as u32 == $class::section_header::SHT_STRTAB {
                strtab = try!($class::strtab::Strtab::parse($fd, shdr.sh_offset as usize, shdr.sh_size as usize, 0x0));
            }
        }

        let strtab_idx = header.e_shstrndx as usize;
        let shdr_strtab = if strtab_idx >= section_headers.len() {
            $class::strtab::Strtab::default()
        } else {
            let shdr = &section_headers[strtab_idx];
            try!($class::strtab::Strtab::parse($fd, shdr.sh_offset as usize, shdr.sh_size as usize, 0x0))
        };

        let mut soname = None;
        let mut libraries = vec![];
        let mut dynsyms = vec![];
        let mut rela = vec![];
        let mut pltrela = vec![];
        let mut dynstrtab = $class::strtab::Strtab::default();
        if let Some(ref dynamic) = dynamic {
            let dyn_info = $class::dyn::DynamicInfo::new(&*dynamic.as_slice(), bias); // we explicitly overflow the values here with our bias
            dynstrtab = try!($class::strtab::Strtab::parse($fd,
                                                           dyn_info.strtab,
                                                           dyn_info.strsz,
                                                           0x0));

            if dyn_info.soname != 0 {
                soname = Some(dynstrtab.get(dyn_info.soname).to_owned())
            }
            if dyn_info.needed_count > 0 {
                let needed = unsafe { $class::dyn::get_needed(dynamic, &dynstrtab, dyn_info.needed_count)};
                libraries = Vec::with_capacity(dyn_info.needed_count);
                for lib in needed {
                    libraries.push(lib.to_owned());
                }
            }
            let num_syms = (dyn_info.strtab - dyn_info.symtab) / dyn_info.syment;
            dynsyms = try!($class::sym::parse($fd, dyn_info.symtab, num_syms, is_lsb));
            rela = try!($class::rela::parse($fd, dyn_info.rela, dyn_info.relasz, is_lsb));
            pltrela = try!($class::rela::parse($fd, dyn_info.jmprel, dyn_info.pltrelsz, is_lsb));
        }
        Ok(Elf {
            header: wrap!( $class, header),
            program_headers: elf_list!( $class, program_headers),
            section_headers: elf_list!( $class, section_headers),
            shdr_strtab: shdr_strtab,
            dynamic: wrap_dyn!($class, dynamic),
            dynsyms: elf_list!($class, dynsyms),
            dynstrtab: dynstrtab,
            syms: elf_list!($class, syms),
            strtab: strtab,
            rela: elf_list!($class, rela),
            pltrela: elf_list!($class, pltrela),
            soname: soname,
            interpreter: interpreter,
            libraries: libraries,
            is_64: is_64,
            is_lib: is_lib,
            entry: entry as u64,
            bias: bias as u64,
            little_endian: is_lsb,
        })
    }};
}

    impl Elf {
        /// Parses the contents of the byte stream in `cursor`, and maybe returns
        /// a unified binary. For better performance, consider using [`from`](#method.from)
        pub fn parse<R: Read + Seek>(cursor: &mut R) -> io::Result<Self> {
            match try!(header::peek(cursor)) {
                (header::ELFCLASS32, _is_lsb) => {
                    parse_impl!(elf32, cursor)
                },
                (header::ELFCLASS64, _is_lsb) => {
                    parse_impl!(elf64, cursor)
                },
                (class, is_lsb) => {
                    io_error!("Unknown values in ELF ident header: class: {} is_lsb: {}",
                          class,
                          is_lsb)
                }
            }
        }
        /// Returns a unified ELF binary from `path`. Allocates an in-memory byte array the size of
        /// the binary at `path` to increase performance.
        pub fn from (path: &Path) -> io::Result<Self> {
            let mut fd = try!(File::open(path));
            let mut bytes = Vec::new();
            try!(fd.read_to_end(&mut bytes));
            let mut cursor = Cursor::new(&bytes);
            Elf::parse(&mut cursor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    #[test]
    fn endian_trait_parse() {
        let crt1: Vec<u8> = include!("../../etc/crt1.rs");
        let mut cursor = Cursor::new(crt1);
        match Elf::parse(&mut cursor) {
            Ok (binary) => {
                assert!(true);
                assert!(binary.is_64);
                assert!(!binary.is_lib);
                assert_eq!(binary.entry, 0);
                assert_eq!(binary.bias, 0);
                let syms = binary.syms;
                let mut i = 0;
                for sym in &syms {
                    if i == 11 {
                        let symtab = binary.strtab;
                        assert_eq!(&symtab[sym.st_name() as usize], "_start");
                        break;
                    }
                    i += 1;
                }
                assert!(syms.len() != 0);
             },
            Err (_) => {
                assert!(false)
            }
        }
    }
}
