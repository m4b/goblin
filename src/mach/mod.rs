//! The mach module: Work in Progress!

extern crate scroll;

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

#[derive(Debug)]
pub struct Mach {
    pub header: header::Header,
}

impl Mach {
    fn get_header<S: scroll::Scroll>(buffer: &S,
                  offset: usize,
                  size: usize,
                  path_str: &::std::ffi::OsStr,
    le: bool)
                  -> io::Result<Mach> {
        if size < header::SIZEOF_MACH_HEADER as usize {
            let error = io::Error::new(io::ErrorKind::Other,
                                       format!("{:?} size is smaller than an Mach-o header",
                                               path_str));
            Err(error)
        } else {
            let header = header::Header::parse(buffer, offset, le)?;
            Ok(Mach { header: header })
        }
    }

    pub fn from(path: &Path) -> io::Result<Mach> {
        let buffer = scroll::Buffer::from(File::open(&path)?)?;
        let size = buffer.len();
        let path_str = path.as_os_str();

        if size < 4 {
            let error = io::Error::new(io::ErrorKind::Other,
                                       format!("{:?} size is smaller than a magical number",
                                               path_str));
            return Err(error);
        }
        let magic = utils::peek_magic(&buffer)?;
        match magic {
            fat::FAT_CIGAM => {
                let arches = fat::FatArch::parse(&buffer)?;
                println!("{:?}", arches);
                if let Some(arch) = fat::FatArch::find_64(&arches) {
                    Self::get_header(&buffer, arch.offset as usize, arch.size as usize, path_str, true)
                } else {
                    let error = io::Error::new(io::ErrorKind::Other,
                                               format!("{:?} does not contain an x86_64 binary",
                                                       path_str));
                    Err(error)
                }
            }
            header::MH_CIGAM_64 => Self::get_header(&buffer, 0, size as usize, path_str, true),
            header::MH_MAGIC_64 => Self::get_header(&buffer, 0, size as usize, path_str, false),
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
