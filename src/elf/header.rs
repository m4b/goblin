use std::mem;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::io;

pub const EHDR_SIZE: usize = 64;

pub const ET_NONE: u16 = 0; // No file type
pub const ET_REL: u16 = 1; // Relocatable file
pub const ET_EXEC: u16 = 2; // Executable file
pub const ET_DYN: u16 = 3; // Shared object file
pub const ET_CORE: u16 = 4; // Core file
pub const ET_NUM: u16 = 5; // Number of defined types

#[inline]
fn et_to_str(et: u16) -> &'static str {
    match et {
        ET_NONE => "NONE",
        ET_REL => "REL",
        ET_EXEC => "EXEC",
        ET_DYN => "DYN",
        ET_CORE => "CORE",
        ET_NUM => "NUM",
        _ => "UNKNOWN_ET",
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "e_ident: {:?} e_type: {} e_machine: 0x{:x} e_version: 0x{:x} e_entry: 0x{:x} \
                e_phoff: 0x{:x} e_shoff: 0x{:x} e_flags: {:x} e_ehsize: {} e_phentsize: {} \
                e_phnum: {} e_shentsize: {} e_shnum: {} e_shstrndx: {}",
               self.e_ident,
               et_to_str(self.e_type),
               self.e_machine,
               self.e_version,
               self.e_entry,
               self.e_phoff,
               self.e_shoff,
               self.e_flags,
               self.e_ehsize,
               self.e_phentsize,
               self.e_phnum,
               self.e_shentsize,
               self.e_shnum,
               self.e_shstrndx)
    }
}

impl Header {
    /// Returns the corresponding ELF header from the given byte array
    pub fn from_bytes(bytes: &[u8; EHDR_SIZE]) -> Header {
        // this is not unsafe because the header's size is encoded in the function, although the header can be semantically invalid
        let header: &Header = unsafe { mem::transmute(bytes) };
        header.clone()
    }

#[cfg(not(feature = "no_endian_fd"))]
    pub fn from_fd(fd: &mut File) -> io::Result<Header> {
        let mut elf_header = [0; EHDR_SIZE];
        use std::io::Cursor;
        use byteorder::{BigEndian, ReadBytesExt};
        let mut rdr = Cursor::new(vec![2, 5, 3, 0]);
        assert_eq!(517, rdr.read_u16::<BigEndian>().unwrap());
        assert_eq!(768, rdr.read_u16::<BigEndian>().unwrap());
        try!(fd.read(&mut elf_header));
        Ok(Header::from_bytes(&elf_header))
    }

#[cfg(feature = "no_endian_fd")]
    pub fn from_fd(fd: &mut File) -> io::Result<Header> {
        let mut elf_header = [0; EHDR_SIZE];
        try!(fd.read(&mut elf_header));
        Ok(Header::from_bytes(&elf_header))
    }

}
