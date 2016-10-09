//! The mach module: Work in Progress!

pub mod header;
pub mod constants;
pub mod fat;
pub mod utils;
// pub mod section;
// pub mod load_command;
// pub mod symbol;


use std::path::Path;
use std::fs::File;
use std::io;
// use std::io::Read;
// use std::io::Seek;
// use std::io::SeekFrom::Start;

#[derive(Debug)]
pub struct Mach {
    pub header: header::Header,
}

impl Mach {
    fn get_header(mut fd: File,
                  offset: u64,
                  size: usize,
                  path_str: &::std::ffi::OsStr)
                  -> io::Result<Mach> {
        if size < header::SIZEOF_MACH_HEADER as usize {
            let error = io::Error::new(io::ErrorKind::Other,
                                       format!("{:?} size is smaller than an Mach-o header",
                                               path_str));
            Err(error)
        } else {
            let header = try!(header::Header::from_fd(&mut fd, offset));
            Ok(Mach { header: header })
        }
    }

    pub fn from_path(path: &Path) -> io::Result<Mach> {
        let mut fd = try!(File::open(&path));
        let metadata = fd.metadata().unwrap();

        let size = metadata.len();
        let path_str = path.as_os_str();

        if size < 4 {
            let error = io::Error::new(io::ErrorKind::Other,
                                       format!("{:?} size is smaller than a magical number",
                                               path_str));
            return Err(error);
        }
        let magic = try!(utils::peek_magic(&mut fd));
        match magic {
            fat::FAT_CIGAM => {
                let arches = try!(fat::FatArch::from_path(path));
                println!("{:?}", arches);
                if let Some(arch) = fat::FatArch::find_64(&arches) {
                    Self::get_header(fd, arch.offset as u64, arch.size as usize, path_str)
                } else {
                    let error = io::Error::new(io::ErrorKind::Other,
                                               format!("{:?} does not contain an x86_64 binary",
                                                       path_str));
                    Err(error)
                }
            }
            header::MH_CIGAM_64 |
            header::MH_MAGIC_64 => Self::get_header(fd, 0, size as usize, path_str),
            magic => {
                let error = io::Error::new(io::ErrorKind::Other,
                                           format!("{:?} unknown magic number: 0x{:x}",
                                                   path_str,
                                                   magic));
                Err(error)
            }
        }
    }
}
