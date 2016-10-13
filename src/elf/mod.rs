//! Access ELF constants, other helper functions, which are independent of ELF bithood.  Also
//! provides parser which returns a wrapped `Elf64` or `Elf32` binary.
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
//!   match goblin::elf::from_fd(fd) {
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
//! To use the automagic ELF datatype union parser, you _must_ enable both elf and
//! elf32 features - i.e., do not use `no_elf` **NOR** `no_elf32`, otherwise you'll get obscure
//! errors about [goblin::elf::from_fd](fn.from_fd.html) missing.

#[cfg(not(feature = "pure"))]
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

#[cfg(all(not(feature = "pure"), not(feature = "no_elf32"), not(feature = "no_elf")))]
pub use self::impure::*;

#[cfg(all(not(feature = "pure"), not(feature = "no_elf32"), not(feature = "no_elf")))]
#[macro_use]
mod impure {

    use std::fs::File;
    use std::io;
    // use std::io::Read;
    // use std::io::SeekFrom::Start;

    use super::header;

    use elf32;
    use elf64;

    macro_rules! wrap {
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

    macro_rules! wrap_iterator {
      ($container:ident, $elem:ident) => {
         impl IntoIterator for $container {
            type Item = $elem;
            type IntoIter = ::std::vec::IntoIter<$elem>;
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

    macro_rules! get_field {
      ($name:ident, $field:ident, $cast:ty) => {
        pub fn $field(&self) -> $cast {
          match self {
            &$name::Elf32(ref st) => st.$field as $cast,
            &$name::Elf64(ref st) => st.$field as $cast,
          }
        }
      }
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
    (st_value, u64),
    (st_name, usize)
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

    #[derive(Debug)]
    pub enum Binary {
        Elf32(elf32::Binary),
        Elf64(elf64::Binary),
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

    impl Binary {
        get_field!(Binary, is_64, bool);
        get_field!(Binary, is_lib, bool);
        get_field!(Binary, entry, u64);
        get_field!(Binary, bias, u64);
        get_field!(Binary, size, usize);

        get_unwrapped_field!(Binary, soname, Option<String>);
        get_unwrapped_field!(Binary, interpreter, Option<String>);

        get_collection!(Binary, Header, header);
        get_collection!(Binary, ProgramHeaders, program_headers);
        get_collection!(Binary, Syms, dynsyms);
        get_collection!(Binary, Syms, syms);
        get_collection!(Binary, Relas, rela);
        get_collection!(Binary, Pltrelas, pltrela);

        get_strtab!(dynstrtab);
        get_strtab!(strtab);
        get_strtab!(shdr_strtab);
    }

    pub fn from_fd(fd: &mut File) -> io::Result<Binary> {
        match try!(header::peek(fd)) {
            (header::ELFCLASS64, _is_lsb) => Ok(Binary::Elf64(try!(elf64::Binary::from_fd(fd)))),
            (header::ELFCLASS32, _is_lsb) => Ok(Binary::Elf32(try!(elf32::Binary::from_fd(fd)))),
            (class, is_lsb) => {
                io_error!("Unknown values in ELF ident header: class: {} is_lsb: {}",
                          class,
                          is_lsb)
            }
        }
    }
}

macro_rules! elf_from_fd { ($intmax:expr) => {
    use std::path::Path;
    use std::fs::File;
    use std::io;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom::Start;

    pub use elf::strtab;
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
        pub size: usize,
        pub entry: usize,
        pub bias: usize,
    }

    impl Binary {

        pub fn from_fd (fd: &mut File) -> io::Result<Binary> {
            let header = try!(header::Header::from_fd(fd));
            let entry = header.e_entry as usize;
            let is_lib = header.e_type == header::ET_DYN;
            let is_lsb = header.e_ident[header::EI_DATA] == header::ELFDATA2LSB;
            let is_64 = header.e_ident[header::EI_CLASS] == header::ELFCLASS64;

            let program_headers = try!(program_header::ProgramHeader::from_fd(fd, header.e_phoff as u64, header.e_phnum as usize, is_lsb));

            let dynamic = try!(dyn::from_fd(fd, &program_headers, is_lsb));
            let mut bias: usize = 0;
            for ph in &program_headers {
                if ph.p_type == program_header::PT_LOAD {
// this is an overflow hack that allows us to use virtual memory addresses as though they're in the file by generating a fake load bias which is then used to overflow the values in the dynamic array, and in a few other places (see Dyn::DynamicInfo), to generate actual file offsets; you may have to marinate a bit on why this works. i am unsure whether it works in every conceivable case. i learned this trick from reading too much dynamic linker C code (a whole other class of C code) and having to deal with broken older kernels on VMs. enjoi
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

            let section_headers = try!(section_header::SectionHeader::from_fd(fd, header.e_shoff as u64, header.e_shnum as usize, is_lsb));

            let mut syms = vec![];
            let mut strtab = strtab::Strtab::default();
            for shdr in &section_headers {
                if shdr.sh_type as u32 == section_header::SHT_SYMTAB {
                    let count = shdr.sh_size / shdr.sh_entsize;
                    syms = try!(sym::from_fd(fd, shdr.sh_offset as usize, count as usize, is_lsb))
                }
                if shdr.sh_type as u32 == section_header::SHT_STRTAB {
                    strtab = try!(strtab::Strtab::from_fd(fd, shdr.sh_offset as usize, shdr.sh_size as usize));
                }
            }

            let strtab_idx = header.e_shstrndx as usize;
            let shdr_strtab = if strtab_idx >= section_headers.len() {
                strtab::Strtab::default()
            } else {
                let shdr = &section_headers[strtab_idx];
                try!(strtab::Strtab::from_fd(fd, shdr.sh_offset as usize, shdr.sh_size as usize))
            };

            let mut soname = None;
            let mut libraries = vec![];
            let mut dynsyms = vec![];
            let mut rela = vec![];
            let mut pltrela = vec![];
            let mut dynstrtab = strtab::Strtab::default();
            if let Some(ref dynamic) = dynamic {
                let dyn_info = dyn::DynamicInfo::new(&dynamic, bias); // we explicitly overflow the values here with our bias
                dynstrtab = try!(strtab::Strtab::from_fd(fd,
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
                dynsyms = try!(sym::from_fd(fd, dyn_info.symtab, num_syms, is_lsb));
                rela = try!(rela::from_fd(fd, dyn_info.rela, dyn_info.relasz, is_lsb));
                pltrela = try!(rela::from_fd(fd, dyn_info.jmprel, dyn_info.pltrelsz, is_lsb));
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
                size: fd.metadata().unwrap().len() as usize,
                entry: entry,
                bias: bias,
            };

            Ok(elf)
        }

        pub fn from_path(path: &Path) -> io::Result<Binary> {
            let mut fd = try!(File::open(&path));
            let metadata = fd.metadata().unwrap();
            if metadata.len() < header::SIZEOF_EHDR as u64 {
                io_error!("Error: {:?} size is smaller than an ELF header", path.as_os_str())
            } else {
                Self::from_fd(&mut fd)
            }
        }
    }
};}
