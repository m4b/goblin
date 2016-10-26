//! Access ELF constants, other helper functions, which are independent of ELF bithood.  Also
//! provides [`parse`](fn.parse.html) which returns a wrapped `Elf64` or `Elf32` binary.
//!
//! To access the contents of the binary, instead of directly getting the struct fields, you call
//! the similarly named methods.
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
//! See [goblin::elf::Binary](enum.Binary.html) for more information.
//!
//! You are still free to use the specific 32-bit or 64-bit versions by accessing them through `goblin::elf64`, etc.
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
    use std::vec;
    use std::ops::Deref;

    use super::header;
    use super::strtab::Strtab;

    use elf32;
    use elf64;

    #[derive(Debug, Copy, Clone)]
    pub enum Header {
        Elf32(elf32::header::Header),
        Elf64(elf64::header::Header),
    }

    impl Deref for Header {
        type Target = super::header::ElfHeader;
        fn deref(&self) -> &Self::Target {
            match *self {
                Header::Elf32(ref header) => {
                    header
                },
                Header::Elf64(ref header) => {
                    header
                }
            }
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub enum Dyn {
        Elf32(elf32::dyn::Dyn),
        Elf64(elf64::dyn::Dyn),
    }

    impl Deref for Sym {
        type Target = super::sym::ElfSym;
        fn deref(&self) -> &Self::Target {
            match *self {
                Sym::Elf32(ref thing) => {
                    thing
                },
                Sym::Elf64(ref thing) => {
                    thing
                }
            }
        }
    }


    #[derive(Debug, Copy, Clone)]
    pub enum Sym {
        Elf32(elf32::sym::Sym),
        Elf64(elf64::sym::Sym),
    }

    impl Deref for Dyn {
        type Target = super::dyn::ElfDyn;
        fn deref(&self) -> &Self::Target {
            match *self {
                Dyn::Elf32(ref thing) => {
                    thing
                },
                Dyn::Elf64(ref thing) => {
                    thing
                }
            }
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub enum Phdr {
        Elf32(elf32::program_header::ProgramHeader),
        Elf64(elf64::program_header::ProgramHeader),
    }

    impl Deref for Phdr {
        type Target = super::program_header::ElfProgramHeader;
        fn deref(&self) -> &Self::Target {
            match *self {
                Phdr::Elf32(ref thing) => {
                    thing
                },
                Phdr::Elf64(ref thing) => {
                    thing
                }
            }
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub enum Shdr {
        Elf32(elf32::section_header::SectionHeader),
        Elf64(elf64::section_header::SectionHeader),
    }

    impl Deref for Shdr {
        type Target = super::section_header::ElfSectionHeader;
        fn deref(&self) -> &Self::Target {
            match *self {
                Shdr::Elf32(ref thing) => {
                    thing
                },
                Shdr::Elf64(ref thing) => {
                    thing
                }
            }
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub enum Rela {
        Elf32(elf32::rela::Rela),
        Elf64(elf64::rela::Rela),
    }

    impl Deref for Rela {
        type Target = super::rela::ElfRela;
        fn deref(&self) -> &Self::Target {
            match *self {
                Rela::Elf32(ref thing) => {
                    thing
                },
                Rela::Elf64(ref thing) => {
                    thing
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct WrappedIterator<T> {
        count: usize,
        iter: vec::IntoIter<T>,
    }

    impl<T> Iterator for WrappedIterator<T> {
        type Item = T;
        fn next(&mut self) -> Option<T> {
            self.iter.next()
        }
    }

    impl<T> ExactSizeIterator for WrappedIterator<T> {
        fn len(&self) -> usize {
            self.count
        }
    }

    #[derive(Debug)]
    pub struct Elf {
        pub header: Header,
        pub program_headers: WrappedIterator<Phdr>,
        pub section_headers: WrappedIterator<Shdr>,
        pub shdr_strtab: Strtab<'static>,
        pub dynstrtab: Strtab<'static>,
        pub dynsyms: WrappedIterator<Sym>,
        pub syms: WrappedIterator<Sym>,
        pub strtab: Strtab<'static>,
        pub dynamic: Option<WrappedIterator<Dyn>>,
        pub rela: WrappedIterator<Rela>,
        pub pltrela: WrappedIterator<Rela>,
        pub soname: Option<String>,
        pub interpreter: Option<String>,
        pub libraries: Vec<String>,
        pub is_64: bool,
        pub is_lib: bool,
        pub entry: u64,
        pub bias: u64,
    }

    macro_rules! wrap_iter {
      ($class:ident, $wrapper:ident, $collection:ident) => {{
                let count = $collection.len();
                let wrapped: Vec<$wrapper> = $collection.into_iter().map(|item| { wr!($class, $wrapper, item) }).collect();
                WrappedIterator {
                    count: count,
                    iter: wrapped.into_iter(),
                }
      }}
    }
    macro_rules! wr {
        (elf32, $wrapper:ident , $item:ident) => {
                 $wrapper::Elf32($item)
        };
        (elf64, $wrapper:ident , $item:ident) => {
                 $wrapper::Elf64($item)
        }
    }
    macro_rules! wrap_dyn {
      ($class:ident, $dynamic:ident) => {{
            if let Some(dynamic) = $dynamic {
                let count = dynamic.len();
                let dyns: Vec<Dyn> = dynamic.into_iter().map(|dyn| wr!($class, Dyn, dyn) ).collect();
                Some (WrappedIterator {
                    count: count,
                    iter: dyns.into_iter(),
                })
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
            let dyn_info = $class::dyn::DynamicInfo::new(&dynamic, bias); // we explicitly overflow the values here with our bias
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
            header: wr!( $class, Header, header),
            program_headers: wrap_iter!( $class, Phdr, program_headers),
            section_headers: wrap_iter!( $class, Shdr, section_headers),
            shdr_strtab: shdr_strtab,
            dynamic: wrap_dyn!($class, dynamic),
            dynsyms: wrap_iter!($class, Sym, dynsyms),
            dynstrtab: dynstrtab,
            syms: wrap_iter!($class, Sym, syms),
            strtab: strtab,
            rela: wrap_iter!($class, Rela, rela),
            pltrela: wrap_iter!($class, Rela, pltrela),
            soname: soname,
            interpreter: interpreter,
            libraries: libraries,
            is_64: is_64,
            is_lib: is_lib,
            entry: entry as u64,
            bias: bias as u64
        })
    }};
}

    impl Elf {
        pub fn parse<R: Read + Seek>(fd: &mut R) -> io::Result<Self> {
            match try!(header::peek(fd)) {
                (header::ELFCLASS32, _is_lsb) => {
                    parse_impl!(elf32, fd)
                },
                (header::ELFCLASS64, _is_lsb) => {
                    parse_impl!(elf64, fd)
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
                for sym in syms {
                    if i == 11 {
                        let symtab = binary.strtab;
                        assert_eq!(&symtab[sym.st_name() as usize], "_start");
                        break;
                    }
                    i += 1;
                }
             },
            Err (_) => {
                assert!(false)
            }
        }
    }
}