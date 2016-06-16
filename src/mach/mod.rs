pub mod header;
//pub mod section;
//pub mod load_command;
//pub mod symbol;
//pub mod fat;

use std::path::Path;
use std::fs::File;
use std::io;
//use std::io::Read;
//use std::io::Seek;
//use std::io::SeekFrom::Start;

#[derive(Debug)]
pub struct Mach {
    pub header: header::Header,
}

impl Mach {
    pub fn from_path<'a>(path: &Path) -> io::Result<Mach> {
        let mut fd = try!(File::open(&path));
        let metadata = fd.metadata().unwrap();
        if metadata.len() < header::SIZEOF_MACH_HEADER as u64 {
            let error = io::Error::new(io::ErrorKind::Other,
                                       format!("Error: {:?} size is smaller than an Mach-o header", path.as_os_str()));
            Err(error)
        } else {
            let header = try!(header::Header::from_fd(&mut fd));
            Ok(Mach {
                header: header,
            })
        }
    }
}
