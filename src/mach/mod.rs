//! The mach module: Work in Progress!

use std::io::Read;
use scroll;

use error;

pub mod header;
pub mod constants;
pub mod fat;
pub mod utils;
// pub mod section;
// pub mod load_command;
// pub mod symbol;

#[derive(Debug)]
pub struct Mach {
    pub header: header::Header,
}

impl Mach {
    fn get_header<S: AsRef<[u8]>>(buffer: &S,
                  offset: usize,
                  size: usize,
                  le: scroll::Endian)
                  -> error::Result<Mach> {
        if size < header::SIZEOF_MACH_HEADER as usize {
            let error = error::Error::Malformed(
                                       format!("size is smaller than an Mach-o header"));
            Err(error)
        } else {
            let header = header::Header::parse(buffer, offset, le)?;
            Ok(Mach { header: header })
        }
    }

    pub fn try_from<R: Read>(fd: &mut R) -> error::Result<Mach> {
        let buffer = scroll::Buffer::try_from(fd)?;
        let size = buffer.len();

        if size < 4 {
            let error = error::Error::Malformed(
                                       format!("size is smaller than a magical number"));
            return Err(error);
        }
        let magic = utils::peek_magic(&buffer)?;
        match magic {
            fat::FAT_CIGAM => {
                let arches = fat::FatArch::parse(&buffer)?;
                println!("{:?}", arches);
                if let Some(arch) = fat::FatArch::find_64(&arches) {
                    Self::get_header(&buffer, arch.offset as usize, arch.size as usize, scroll::LE)
                } else {
                    let error = error::Error::Malformed(format!("Does not contain an x86_64 binary"));
                    Err(error)
                }
            },
            header::MH_CIGAM_64 => Self::get_header(&buffer, 0, size as usize, scroll::LE),
            header::MH_MAGIC_64 => Self::get_header(&buffer, 0, size as usize, scroll::BE),
            magic => {
                let error = error::Error::BadMagic(magic as u64);
                Err(error)
            }
        }
    }
}
