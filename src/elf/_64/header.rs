use std::mem;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::io;

pub use super::super::elf::header::*;

#[repr(C)]
#[derive(Clone, Default)]
pub struct Header {
    pub e_ident: [u8; SIZEOF_IDENT],
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

pub const SIZEOF_EHDR: usize = 64;

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
    pub fn from_bytes(bytes: &[u8; SIZEOF_EHDR]) -> Header {
        // this is not unsafe because the header's size is encoded in the function, although the header can be semantically invalid
        let header: &Header = unsafe { mem::transmute(bytes) };
        header.clone()
    }

    #[cfg(not(feature = "no_endian_fd"))]
    pub fn from_fd(fd: &mut File) -> io::Result<Header> {
        use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
        use std::io::Seek;
        use std::io::SeekFrom::Start;
        let mut elf_header = Header::default();

        elf_header.e_ident = [0; SIZEOF_IDENT];
        try!(fd.seek(Start(0)));
        try!(fd.read(&mut elf_header.e_ident));

        match elf_header.e_ident[EI_DATA] {
            ELFDATA2LSB => {
                elf_header.e_type = try!(fd.read_u16::<LittleEndian>());
                elf_header.e_machine = try!(fd.read_u16::<LittleEndian>());
                elf_header.e_version = try!(fd.read_u32::<LittleEndian>());
                elf_header.e_entry = try!(fd.read_u64::<LittleEndian>());
                elf_header.e_phoff = try!(fd.read_u64::<LittleEndian>());
                elf_header.e_shoff = try!(fd.read_u64::<LittleEndian>());
                elf_header.e_flags = try!(fd.read_u32::<LittleEndian>());
                elf_header.e_ehsize = try!(fd.read_u16::<LittleEndian>());
                elf_header.e_phentsize = try!(fd.read_u16::<LittleEndian>());
                elf_header.e_phnum = try!(fd.read_u16::<LittleEndian>());
                elf_header.e_shentsize = try!(fd.read_u16::<LittleEndian>());
                elf_header.e_shnum = try!(fd.read_u16::<LittleEndian>());
                elf_header.e_shstrndx = try!(fd.read_u16::<LittleEndian>());
                Ok(elf_header)
            },
            ELFDATA2MSB => {
                elf_header.e_type = try!(fd.read_u16::<BigEndian>());
                elf_header.e_machine = try!(fd.read_u16::<BigEndian>());
                elf_header.e_version = try!(fd.read_u32::<BigEndian>());
                elf_header.e_entry = try!(fd.read_u64::<BigEndian>());
                elf_header.e_phoff = try!(fd.read_u64::<BigEndian>());
                elf_header.e_shoff = try!(fd.read_u64::<BigEndian>());
                elf_header.e_flags = try!(fd.read_u32::<BigEndian>());
                elf_header.e_ehsize = try!(fd.read_u16::<BigEndian>());
                elf_header.e_phentsize = try!(fd.read_u16::<BigEndian>());
                elf_header.e_phnum = try!(fd.read_u16::<BigEndian>());
                elf_header.e_shentsize = try!(fd.read_u16::<BigEndian>());
                elf_header.e_shnum = try!(fd.read_u16::<BigEndian>());
                elf_header.e_shstrndx = try!(fd.read_u16::<BigEndian>());
                Ok(elf_header)
            },
            d => Err(io::Error::new(io::ErrorKind::Other, format!("Invalid ELF DATA type {:x}",d))),
        }
    }

    #[cfg(feature = "no_endian_fd")]
    pub fn from_fd(fd: &mut File) -> io::Result<Header> {
        let mut elf_header = [0; SIZEOF_EHDR];
        try!(fd.read(&mut elf_header));
        Ok(Header::from_bytes(&elf_header))
    }

}
