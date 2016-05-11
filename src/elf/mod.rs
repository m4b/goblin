pub mod header;
pub mod program_header;
pub mod dyn;
pub mod rela;
pub mod sym;
pub mod strtab;
pub mod gnu_hash;

use std::path::Path;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom::Start;

#[derive(Debug)]
pub struct Elf {
    pub header: header::Header,
    pub program_headers: Vec<program_header::ProgramHeader>,
    pub dynamic: Option<Vec<dyn::Dyn>>,
    pub symtab: Vec<sym::Sym>,
    pub rela: Vec<rela::Rela>,
    pub pltrela: Vec<rela::Rela>,
    pub soname: Option<String>,
    pub interpreter: Option<String>,
    pub libraries: Vec<String>,
    pub is_lib: bool,
    pub size: usize,
    pub entry: usize,
}

impl Elf {
    pub fn from_path<'a>(path: &Path) -> io::Result<Elf> {
        let mut fd = try!(File::open(&path));
        let metadata = fd.metadata().unwrap();
        if metadata.len() < header::EHDR_SIZE as u64 {
            let error = io::Error::new(io::ErrorKind::Other,
                                       format!("Error: {:?} size is smaller than an ELF header",
                                               path.as_os_str()));
            Err(error)
        } else {
            let mut elf_header = [0; header::EHDR_SIZE];
            try!(fd.read(&mut elf_header));

            let header = header::Header::from_bytes(&elf_header);
            let entry = header.e_entry as usize;
            let is_lib = header.e_type == header::ET_DYN;

            let mut bytes = vec![0u8; ((header.e_phnum * header.e_phentsize) as usize)];
            try!(fd.seek(Start(header.e_phoff)));
            try!(fd.read(&mut bytes));

            let program_headers =
                program_header::ProgramHeader::from_bytes(bytes, header.e_phnum as usize);

            let dynamic = try!(dyn::from_fd(&mut fd, &program_headers));

            let mut bias: usize = 0;
            for ph in &program_headers {
                if ph.p_type == program_header::PT_LOAD {
                    bias = ((::std::u64::MAX - ph.p_vaddr).wrapping_add(1)) as usize; // my name's David
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

            //            let mut strtab = None;
            //            let mut symtab = None;
            let mut soname = None;
            let mut libraries = vec![];
            let mut symtab = vec![];
            let mut rela = vec![];
            let mut pltrela = vec![];
            if let Some(ref dynamic) = dynamic {
                let link_info = dyn::LinkInfo::new(&dynamic, bias); // we explicitly overflow the values here with our bias
                let strtab = try!(strtab::Strtab::from_fd(&mut fd,
                                                          link_info.strtab,
                                                          link_info.strsz));
                let soname_ = strtab.get(link_info.soname).to_owned();
                if soname_ != "" {
                    soname = Some(soname_)
                }
                let needed = dyn::get_needed(dynamic, &strtab, link_info.needed_count);
                libraries = Vec::with_capacity(link_info.needed_count);
                for lib in needed {
                    libraries.push(lib.to_owned());
                }

                let num_syms = (link_info.strtab - link_info.symtab) / link_info.syment; // old caveat about how this is probably not safe but rdr has been doing it with tons of binaries and never any problems
                symtab = try!(sym::from_fd(&mut fd, link_info.symtab, num_syms));

                rela = try!(rela::from_fd(&mut fd, link_info.rela, link_info.relasz));
                pltrela = try!(rela::from_fd(&mut fd, link_info.jmprel, link_info.pltrelsz));

            }

            let elf = Elf {
                header: header,
                program_headers: program_headers,
                dynamic: dynamic,
                symtab: symtab,
                rela: rela,
                pltrela: pltrela,
                soname: soname,
                interpreter: interpreter,
                libraries: libraries,
                is_lib: is_lib,
                size: metadata.len() as usize,
                entry: entry,
            };

            Ok(elf)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use elf;
    #[test]
    fn read_ls() {
        let _ = elf::Elf::from_path(Path::new("/bin/ls"));
    }
}
