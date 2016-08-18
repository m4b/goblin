//! The ELF 64-bit struct definitions and associated values

pub mod header;
pub mod program_header;
pub mod dyn;
pub mod rela;
pub mod sym;

#[cfg(not(feature = "pure"))]
pub mod gnu_hash;

#[cfg(not(feature = "pure"))]
pub use super::elf::strtab;

#[cfg(not(feature = "pure"))]
pub use self::impure::*;

#[cfg(not(feature = "pure"))]
mod impure {

    use std::path::Path;
    use std::fs::File;
    use std::io;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom::Start;

    use super::*;

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

    impl Binary {
        pub fn from_fd (fd: &mut File) -> io::Result<Binary> {
            let header = try!(header::Header::from_fd(fd));
            let entry = header.e_entry as usize;
            let is_lib = header.e_type == header::ET_DYN;
            let is_lsb = header.e_ident[header::EI_DATA] == header::ELFDATA2LSB;

            let program_headers = try!(program_header::ProgramHeader::from_fd(fd, header.e_phoff, header.e_phnum as usize, is_lsb));

            let dynamic = try!(dyn::from_fd(fd, &program_headers, is_lsb));
            let mut bias: usize = 0;
            for ph in &program_headers {
                if ph.p_type == program_header::PT_LOAD {
                    // this is an overflow hack that allows us to use virtual memory addresses as though they're in the file by generating a fake load bias which is then used to overflow the values in the dynamic array, and in a few other places (see Dyn::DynamicInfo), to generate actual file offsets; you may have to marinate a bit on why this works. i am unsure whether it works in every conceivable case. i learned this trick from reading too much dynamic linker C code (a whole other class of C code) and having to deal with broken older kernels on VMs. enjoi
                    bias = ((::std::u64::MAX - ph.p_vaddr).wrapping_add(1)) as usize;
                    break;
                }
            }

            let mut interpreter = None;
            for ph in &program_headers {
                if ph.p_type == program_header::PT_INTERP {
                    let mut bytes = vec![0u8; (ph.p_filesz - 1) as usize];
                    try!(fd.seek(Start(ph.p_offset)));
                    try!(fd.read(&mut bytes));
                    interpreter = Some(String::from_utf8(bytes).unwrap())
                }
            }

            let mut soname = None;
            let mut libraries = vec![];
            let mut symtab = vec![];
            let mut rela = vec![];
            let mut pltrela = vec![];
            let mut strtabv = vec![];
            if let Some(ref dynamic) = dynamic {
                let link_info = dyn::DynamicInfo::new(&dynamic, bias); // we explicitly overflow the values here with our bias
                let strtab = try!(strtab::Strtab::from_fd(fd,
                                                          link_info.strtab,
                                                          link_info.strsz));
                if link_info.soname != 0 {
                    soname = Some(strtab.get(link_info.soname).to_owned())
                }
                if link_info.needed_count > 0 {
                    let needed = dyn::get_needed(dynamic, &strtab, link_info.needed_count);
                    libraries = Vec::with_capacity(link_info.needed_count);
                    for lib in needed {
                        libraries.push(lib.to_owned());
                    }
                }

                let num_syms = (link_info.strtab - link_info.symtab) / link_info.syment; // old caveat about how this is probably not safe but rdr has been doing it with tons of binaries and never any problems
                symtab = try!(sym::from_fd(fd, link_info.symtab, num_syms, is_lsb));

                rela = try!(rela::from_fd(fd, link_info.rela, link_info.relasz, is_lsb));
                pltrela = try!(rela::from_fd(fd, link_info.jmprel, link_info.pltrelsz, is_lsb));
                strtabv = strtab.to_vec();

            }

            let elf = Binary {
                header: header,
                program_headers: program_headers,
                dynamic: dynamic,
                symtab: symtab,
                rela: rela,
                pltrela: pltrela,
                strtab: strtabv,
                soname: soname,
                interpreter: interpreter,
                libraries: libraries,
                is_lib: is_lib,
                size: fd.metadata().unwrap().len() as usize,
                entry: entry,
            };

            Ok(elf)
        }

        pub fn from_path<'a>(path: &Path) -> io::Result<Binary> {
            let mut fd = try!(File::open(&path));
            let metadata = fd.metadata().unwrap();
            if metadata.len() < header::SIZEOF_EHDR as u64 {
                io_error!("Error: {:?} size is smaller than an ELF header", path.as_os_str())
            } else {
                Self::from_fd(&mut fd)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::path::Path;

        #[test]
        fn read_ls() {
            assert!(super::Binary::from_path(Path::new("/bin/ls")).is_ok());
        }
    }
}
