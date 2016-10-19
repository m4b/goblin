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
//!   match goblin::elf::parse(fd) {
//!     Ok(binary) => {
//!       let entry = binary.entry();
//!       for ph in binary.program_headers() {
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

    use std::io::{self, Read, Seek};
    use std::vec;
    use std::ops::Deref;

    use super::header;
    use super::strtab::Strtab;

    use elf32;
    use elf64;

    #[derive(Debug)]
    pub enum Hdr {
        Elf32(elf32::header::Header),
        Elf64(elf64::header::Header),
    }
    impl Deref for Hdr {
        type Target = super::header::ElfHeader;
        fn deref (&self) -> &Self::Target {
            match *self {
                Hdr::Elf32(ref header) => {
                    header
                },
                Hdr::Elf64(ref header) => {
                    header
                }
            }
        }
    }

    #[derive(Debug)]
    pub enum Dynny {
        Elf32(elf32::dyn::Dyn),
        Elf64(elf64::dyn::Dyn),
    }

    impl Deref for Symmy {
        type Target = super::sym::ElfSym;
        fn deref (&self) -> &Self::Target {
            match *self {
                Symmy::Elf32(ref thing) => {
                    thing
                },
                Symmy::Elf64(ref thing) => {
                    thing
                }
            }
        }
    }


    #[derive(Debug)]
    pub enum Symmy {
        Elf32(elf32::sym::Sym),
        Elf64(elf64::sym::Sym),
    }

    impl Deref for Dynny {
        type Target = super::dyn::ElfDyn;
        fn deref (&self) -> &Self::Target {
            match *self {
                Dynny::Elf32(ref thing) => {
                    thing
                },
                Dynny::Elf64(ref thing) => {
                    thing
                }
            }
        }
    }

    #[derive(Debug)]
    pub enum Phdr {
        Elf32(elf32::program_header::ProgramHeader),
        Elf64(elf64::program_header::ProgramHeader),
    }

    impl Deref for Phdr {
        type Target = super::program_header::ElfProgramHeader;
        fn deref (&self) -> &Self::Target {
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

    #[derive(Debug)]
    pub enum Shdr {
        Elf32(elf32::section_header::SectionHeader),
        Elf64(elf64::section_header::SectionHeader),
    }

    impl Deref for Shdr {
        type Target = super::section_header::ElfSectionHeader;
        fn deref (&self) -> &Self::Target {
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

    #[derive(Debug)]
    pub enum Relay {
        Elf32(elf32::rela::Rela),
        Elf64(elf64::rela::Rela),
    }

    impl Deref for Relay {
        type Target = super::rela::ElfRela;
        fn deref (&self) -> &Self::Target {
            match *self {
                Relay::Elf32(ref thing) => {
                    thing
                },
                Relay::Elf64(ref thing) => {
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
        pub header: Hdr,
        pub program_headers: WrappedIterator<Phdr>,
        pub section_headers: WrappedIterator<Shdr>,
        pub shdr_strtab: Strtab<'static>,
        pub dynstrtab: Strtab<'static>,
        pub dynsyms: WrappedIterator<Symmy>,
        pub syms: WrappedIterator<Symmy>,
        pub strtab: Strtab<'static>,
        pub dynamic: Option<WrappedIterator<Dynny>>,
        pub rela: WrappedIterator<Relay>,
        pub pltrela: WrappedIterator<Relay>,
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
                let wrapped: Vec<$wrapper> = $collection.into_iter().map(|item| wr!($class, $wrapper, item) ).collect();
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
                let dyns: Vec<Dynny> = dynamic.into_iter().map(|dyn| wr!($class, Dynny, dyn) ).collect();
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
                strtab = try!($class::strtab::Strtab::parse($fd, shdr.sh_offset as usize, shdr.sh_size as usize));
            }
        }

        let strtab_idx = header.e_shstrndx as usize;
        let shdr_strtab = if strtab_idx >= section_headers.len() {
            $class::strtab::Strtab::default()
        } else {
            let shdr = &section_headers[strtab_idx];
            try!($class::strtab::Strtab::parse($fd, shdr.sh_offset as usize, shdr.sh_size as usize))
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
                                                           dyn_info.strsz));

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
            header: wr!( $class, Hdr, header),
            program_headers: wrap_iter!( $class, Phdr, program_headers),
            section_headers: wrap_iter!( $class, Shdr, section_headers),
            shdr_strtab: shdr_strtab,
            dynamic: wrap_dyn!($class, dynamic),
            dynsyms: wrap_iter!($class, Symmy, dynsyms),
            dynstrtab: dynstrtab,
            syms: wrap_iter!($class, Symmy, syms),
            strtab: strtab,
            rela: wrap_iter!($class, Relay, rela),
            pltrela: wrap_iter!($class, Relay, pltrela),
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

    use std::io::SeekFrom::Start;
    impl Elf {
        pub fn parse<R: Read + Seek> (fd: &mut R) -> io::Result<Self> {

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
    }

    macro_rules! wrap {
        ($list:ident, $name:ident, @optvec $elem:ident) => {
            #[derive(Debug)]
            pub enum $list {
                Elf32(Option<Vec<elf32::$elem::$name>>),
                Elf64(Option<Vec<elf64::$elem::$name>>),
            }
        };
        ($list:ident, $name:ident, @vec $elem:ident) => {
            #[derive(Debug)]
            pub enum $list {
                Elf32(Vec<elf32::$elem::$name>),
                Elf64(Vec<elf64::$elem::$name>),
            }
        };
        ($name:ident, $elem:ident) => {
            #[derive(Debug)]
            pub enum $name {
                Elf32(elf32::$elem::$name),
                Elf64(elf64::$elem::$name),
            }
        };
    }

    wrap!(ProgramHeader, program_header);
    wrap!(SectionHeader, section_header);
    wrap!(Header, header);
    wrap!(Sym, sym);
    wrap!(Dyn, dyn);
    wrap!(Rela, rela);

    wrap!(ProgramHeaders, ProgramHeader, @vec program_header);
    wrap!(SectionHeaders, SectionHeader, @vec section_header);
    wrap!(Dynsyms, Sym, @vec sym);
    wrap!(Syms, Sym, @vec sym);
    wrap!(Relas, Rela, @vec rela);
    wrap!(Pltrelas, Rela, @vec rela);
    wrap!(Dynamic, Dyn, @vec dyn);

    macro_rules! wrap_iterator {
      ($container:ident, $elem:ident) => {
         impl IntoIterator for $container {
            type Item = $elem;
            type IntoIter = vec::IntoIter<$elem>;
            fn into_iter(self) -> Self::IntoIter {
                match self {
                    $container::Elf32(container) => {
                        let elems: Vec<$elem> = container.into_iter().map(|elem| $elem::Elf32(elem)).collect();
                        elems.into_iter()
                    }
                    $container::Elf64(container) => {
                        let elems: Vec<$elem> = container.into_iter().map(|elem| $elem::Elf64(elem)).collect();
                        elems.into_iter()
                    }
                }
            }
        }
      }
    }

    wrap_iterator!(ProgramHeaders, ProgramHeader);
    wrap_iterator!(SectionHeaders, SectionHeader);
    wrap_iterator!(Syms, Sym);
    wrap_iterator!(Relas, Rela);
    wrap_iterator!(Dynamic, Dyn);

    macro_rules! get_field {
      ($name:ident, $field:ident, $cast:ty) => {
        pub fn $field(&self) -> $cast {
          match self {
            &$name::Elf32(ref st) => st.$field as $cast,
            &$name::Elf64(ref st) => st.$field as $cast,
          }
        }
      };
    }

    macro_rules! wrap_impl {
        ($name:ident, $elem:ident, [$(($field:ident, $typ:ty)),*]) => {
            impl $name {
                $(
                  get_field!($name, $field, $typ);
                )*
            }
        }
    }

    wrap_impl!(Header, header, [
    (e_ident, [u8; header::SIZEOF_IDENT]),
    (e_type, u16),
    (e_machine, u16),
    (e_version, u32),
    (e_entry, u64),
    (e_phoff, u64),
    (e_shoff, u64),
    (e_flags, u32),
    (e_ehsize, u16),
    (e_phentsize, u16),
    (e_phnum, u16),
    (e_shentsize, u16),
    (e_shnum, u16),
    (e_shstrndx, u16)
    ]);
    wrap_impl!(ProgramHeader, program_header, [
    (p_type, u32),
    (p_flags, u32),
    (p_offset, u64),
    (p_vaddr, u64),
    (p_paddr, u64),
    (p_filesz, u64),
    (p_memsz, u64),
    (p_align, u64)
    ]);
    wrap_impl!(SectionHeader, section_header, [
    (sh_name, u32),
    (sh_type, u32),
    (sh_flags, u64),
    (sh_addr, u64),
    (sh_offset, u64),
    (sh_size, u64),
    (sh_link, u32),
    (sh_info, u32),
    (sh_addralign, u64),
    (sh_entsize, u64)
    ]);
    wrap_impl!(Sym, sym, [
    (st_name, usize),
    (st_info, u8),
    (st_other, u8),
    (st_shndx, u16),
    (st_value, u64),
    (st_size, u64)
    ]);
    wrap_impl!(Dyn, dyn, [
    (d_tag, u64),
    (d_val, u64)
    ]);
    wrap_impl!(Rela, rela, [
    (r_offset, u64),
    (r_info, u64),
    (r_addend, u64)
    ]);

    // this is a hack cause don't feel like messing with macros
    impl Sym {
        pub fn is_function(&self) -> bool {
          match self {
            &Sym::Elf32(ref st) => st.is_function(),
            &Sym::Elf64(ref st) => st.is_function(),
          }
        }
        pub fn is_import(&self) -> bool {
            match self {
                &Sym::Elf32(ref st) => st.is_import(),
                &Sym::Elf64(ref st) => st.is_import(),
            }
        }
    }

    #[derive(Debug)]
    pub enum Binary {
        Elf32(elf32::Binary),
        Elf64(elf64::Binary),
    }

    // TODO: fix this, clones the vector, when it's nicer to just send a reference back and let callee
    // decide if they want to clone
    macro_rules! get_collection {
        ($name:ident, $memtyp:ident, $field:ident) => {
            pub fn $field(&self) -> $memtyp {
                match self {
                    &$name::Elf32(ref binary) => $memtyp::Elf32(binary.$field.clone()),
                    &$name::Elf64(ref binary) => $memtyp::Elf64(binary.$field.clone()),
                }
            }
        }
    }
    macro_rules! get_strtab {
          ($field:ident) => {
              pub fn $field<'a> (&'a self) -> &'a super::strtab::Strtab<'a> {
                match self {
                    &Binary::Elf32(ref binary) => &binary.$field,
                    &Binary::Elf64(ref binary) => &binary.$field,
                }
              }
          }
    }

    macro_rules! get_unwrapped_field {
          ($name:ident, $field:ident, $typ:ty) => {
              pub fn $field (&self) -> &$typ {
                match self {
                    &Binary::Elf32(ref binary) => &binary.$field,
                    &Binary::Elf64(ref binary) => &binary.$field,
                }
              }
          }
    }

//
//        pub program_headers: Vec<program_header::ProgramHeader>,
//        pub section_headers: Vec<section_header::SectionHeader>,
//        pub shdr_strtab: strtab::Strtab<'static>,
//        pub dynamic: Option<Vec<dyn::Dyn>>,
//        pub dynsyms: Vec<sym::Sym>,
//        pub dynstrtab: strtab::Strtab<'static>,
//        pub syms: Vec<sym::Sym>,
//        pub strtab: strtab::Strtab<'static>,
//        pub rela: Vec<rela::Rela>,
//        pub pltrela: Vec<rela::Rela>,
//        pub soname: Option<String>,
//        pub interpreter: Option<String>,
//        pub libraries: Vec<String>,
//        pub is_64: bool,
//        pub is_lib: bool,
//        pub entry: usize,
//        pub bias: usize,

    impl Binary {
        get_field!(Binary, is_64, bool);
        get_field!(Binary, is_lib, bool);
        get_field!(Binary, entry, u64);
        get_field!(Binary, bias, u64);

        get_unwrapped_field!(Binary, soname, Option<String>);
        get_unwrapped_field!(Binary, interpreter, Option<String>);
        get_unwrapped_field!(Binary, libraries, Vec<String>);

        get_collection!(Binary, Header, header);
        get_collection!(Binary, ProgramHeaders, program_headers);
        get_collection!(Binary, Syms, dynsyms);
        get_collection!(Binary, Syms, syms);
        get_collection!(Binary, Relas, rela);
        get_collection!(Binary, Pltrelas, pltrela);

        get_strtab!(dynstrtab);
        get_strtab!(strtab);
        get_strtab!(shdr_strtab);

        pub fn dynamic (&self) -> Option<Dynamic> {
            match self {
                &Binary::Elf32(ref binary) => {
                    if let Some(ref dynamic) = binary.dynamic {
                        Some(Dynamic::Elf32(dynamic.clone()))
                    } else {
                        None
                    }
                },
                &Binary::Elf64(ref binary) => {
                    if let Some(ref dynamic) = binary.dynamic {
                        Some(Dynamic::Elf64(dynamic.clone()))
                    } else {
                        None
                    }
                }
            }
        }
    }

    pub fn parse<R: Read + Seek>(fd: &mut R) -> io::Result<Binary> {
        match try!(header::peek(fd)) {
            (header::ELFCLASS64, _is_lsb) => Ok(Binary::Elf64(try!(elf64::Binary::parse(fd)))),
            (header::ELFCLASS32, _is_lsb) => Ok(Binary::Elf32(try!(elf32::Binary::parse(fd)))),
            (class, is_lsb) => {
                io_error!("Unknown values in ELF ident header: class: {} is_lsb: {}",
                          class,
                          is_lsb)
            }
        }
    }
}

macro_rules! elf_from { ($intmax:expr) => {
    use std::path::Path;
    use std::fs::File;
    use std::io;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom::Start;

    use elf::strtab;
    use super::{header, program_header, section_header, dyn, sym, rela};

    #[derive(Debug)]
    pub struct Binary {
        pub header: header::Header,
        pub program_headers: Vec<program_header::ProgramHeader>,
        pub section_headers: Vec<section_header::SectionHeader>,
        pub shdr_strtab: strtab::Strtab<'static>,
        pub dynamic: Option<Vec<dyn::Dyn>>,
        pub dynsyms: Vec<sym::Sym>,
        pub dynstrtab: strtab::Strtab<'static>,
        pub syms: Vec<sym::Sym>,
        pub strtab: strtab::Strtab<'static>,
        pub rela: Vec<rela::Rela>,
        pub pltrela: Vec<rela::Rela>,
        pub soname: Option<String>,
        pub interpreter: Option<String>,
        pub libraries: Vec<String>,
        pub is_64: bool,
        pub is_lib: bool,
        pub entry: usize,
        pub bias: usize,
    }

    impl Binary {

        pub fn parse<R: Read + Seek> (fd: &mut R) -> io::Result<Binary> {
            let header = try!(header::Header::parse(fd));
            let entry = header.e_entry as usize;
            let is_lib = header.e_type == header::ET_DYN;
            let is_lsb = header.e_ident[header::EI_DATA] == header::ELFDATA2LSB;
            let is_64 = header.e_ident[header::EI_CLASS] == header::ELFCLASS64;

            let program_headers = try!(program_header::ProgramHeader::parse(fd, header.e_phoff as u64, header.e_phnum as usize, is_lsb));

            let dynamic = try!(dyn::parse(fd, &program_headers, is_lsb));
            let mut bias: usize = 0;
            for ph in &program_headers {
                if ph.p_type == program_header::PT_LOAD {
                    // this is an overflow hack that allows us to use virtual memory addresses
                    // as though they're in the file by generating a fake load bias which is then
                    // used to overflow the values in the dynamic array, and in a few other places
                    // (see Dyn::DynamicInfo), to generate actual file offsets; you may have to
                    // marinate a bit on why this works. i am unsure whether it works in every
                    // conceivable case. i learned this trick from reading too much dynamic linker
                    // C code (a whole other class of C code) and having to deal with broken older
                    // kernels on VMs. enjoi
                    bias = (($intmax - ph.p_vaddr).wrapping_add(1)) as usize;
                    break;
                }
            }

            let mut interpreter = None;
            for ph in &program_headers {
                if ph.p_type == program_header::PT_INTERP {
                    let mut bytes = vec![0u8; (ph.p_filesz - 1) as usize];
                    try!(fd.seek(Start(ph.p_offset as u64)));
                    try!(fd.read(&mut bytes));
                    interpreter = Some(String::from_utf8(bytes).unwrap())
                }
            }

            let section_headers = try!(section_header::SectionHeader::parse(fd, header.e_shoff as u64, header.e_shnum as usize, is_lsb));

            let mut syms = vec![];
            let mut strtab = strtab::Strtab::default();
            for shdr in &section_headers {
                if shdr.sh_type as u32 == section_header::SHT_SYMTAB {
                    let count = shdr.sh_size / shdr.sh_entsize;
                    syms = try!(sym::parse(fd, shdr.sh_offset as usize, count as usize, is_lsb))
                }
                if shdr.sh_type as u32 == section_header::SHT_STRTAB {
                    strtab = try!(strtab::Strtab::parse(fd, shdr.sh_offset as usize, shdr.sh_size as usize));
                }
            }

            let strtab_idx = header.e_shstrndx as usize;
            let shdr_strtab = if strtab_idx >= section_headers.len() {
                strtab::Strtab::default()
            } else {
                let shdr = &section_headers[strtab_idx];
                try!(strtab::Strtab::parse(fd, shdr.sh_offset as usize, shdr.sh_size as usize))
            };

            let mut soname = None;
            let mut libraries = vec![];
            let mut dynsyms = vec![];
            let mut rela = vec![];
            let mut pltrela = vec![];
            let mut dynstrtab = strtab::Strtab::default();
            if let Some(ref dynamic) = dynamic {
                let dyn_info = dyn::DynamicInfo::new(&dynamic, bias); // we explicitly overflow the values here with our bias
                dynstrtab = try!(strtab::Strtab::parse(fd,
                                                          dyn_info.strtab,
                                                          dyn_info.strsz));

                if dyn_info.soname != 0 {
                    soname = Some(dynstrtab.get(dyn_info.soname).to_owned())
                }
                if dyn_info.needed_count > 0 {
                    let needed = unsafe { dyn::get_needed(dynamic, &dynstrtab, dyn_info.needed_count)};
                    libraries = Vec::with_capacity(dyn_info.needed_count);
                    for lib in needed {
                        libraries.push(lib.to_owned());
                    }
                }

                let num_syms = (dyn_info.strtab - dyn_info.symtab) / dyn_info.syment;
                dynsyms = try!(sym::parse(fd, dyn_info.symtab, num_syms, is_lsb));
                rela = try!(rela::parse(fd, dyn_info.rela, dyn_info.relasz, is_lsb));
                pltrela = try!(rela::parse(fd, dyn_info.jmprel, dyn_info.pltrelsz, is_lsb));
            }

            let elf = Binary {
                header: header,
                program_headers: program_headers,
                section_headers: section_headers,
                shdr_strtab: shdr_strtab,
                dynamic: dynamic,
                dynsyms: dynsyms,
                dynstrtab: dynstrtab,
                syms: syms,
                strtab: strtab,
                rela: rela,
                pltrela: pltrela,
                soname: soname,
                interpreter: interpreter,
                libraries: libraries,
                is_64: is_64,
                is_lib: is_lib,
                entry: entry,
                bias: bias,
            };

            Ok(elf)
        }

        pub fn from_path(path: &Path) -> io::Result<Binary> {
            let mut fd = try!(File::open(&path));
            let metadata = try!(fd.metadata());
            if metadata.len() < header::SIZEOF_EHDR as u64 {
                io_error!("Error: {:?} size is smaller than an ELF header", path.as_os_str())
            } else {
                Self::parse(&mut fd)
            }
        }
    }
};}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    #[test]
    fn endian_parse() {
        let crt1: Vec<u8> = include!("../../etc/crt1.rs");
        let mut cursor = Cursor::new(crt1);
        match parse(&mut cursor) {
            Ok (binary) => {
                assert!(binary.is_64());
                assert!(!binary.is_lib());
                assert_eq!(binary.entry(), 0);
                assert_eq!(binary.bias(), 0);
                let syms = binary.syms();
                let mut i = 0;
                for sym in syms {
                    if i == 11 {
                        let symtab = binary.strtab();
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