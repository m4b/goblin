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
pub const ELFCLASS: u8 = ELFCLASS64;

elf_header_impure_impl!(
    impl Header {
        elf_header_from_bytes!();
        elf_header_from_fd!();
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
                d => io_error!("Invalid ELF DATA type {:x}", d),
            }
        }
    });
