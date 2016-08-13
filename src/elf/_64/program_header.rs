pub use super::super::elf::program_header::*;

#[repr(C)]
#[derive(Clone, PartialEq, Default)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

pub const SIZEOF_PHDR: usize = 64;

#[cfg(not(feature = "pure"))]
pub use self::impure::*;

#[cfg(not(feature = "pure"))]
mod impure {

    use super::*;

    use std::slice;
    use std::fmt;
    use std::fs::File;
    use std::io::Seek;
    use std::io::SeekFrom::Start;
    use std::io;


    impl fmt::Debug for ProgramHeader {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f,
                   "p_type: {} p_flags 0x{:x} p_offset: 0x{:x} p_vaddr: 0x{:x} p_paddr: 0x{:x} \
                    p_filesz: 0x{:x} p_memsz: 0x{:x} p_align: {}",
                   pt_to_str(self.p_type),
                   self.p_flags,
                   self.p_offset,
                   self.p_vaddr,
                   self.p_paddr,
                   self.p_filesz,
                   self.p_memsz,
                   self.p_align)
        }
    }

    impl ProgramHeader {
        pub fn from_bytes(bytes: &[u8], phnum: usize) -> Vec<ProgramHeader> {
            let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut ProgramHeader, phnum) };
            let mut phdrs = Vec::with_capacity(phnum);
            phdrs.extend_from_slice(bytes);
            phdrs
        }

        pub unsafe fn from_raw_parts<'a>(phdrp: *const ProgramHeader,
                                         phnum: usize)
                                         -> &'a [ProgramHeader] {
            slice::from_raw_parts(phdrp, phnum)
        }

        #[cfg(not(feature = "no_endian_fd"))]
        pub fn from_fd(fd: &mut File, offset: u64, count: usize, is_lsb: bool) -> io::Result<Vec<ProgramHeader>> {
            use byteorder::{LittleEndian,BigEndian,ReadBytesExt};

            let mut phdrs = vec![];
            try!(fd.seek(Start(offset)));
            for _ in 0..count {
                let mut phdr = ProgramHeader::default();
                if is_lsb {
                    phdr.p_type = try!(fd.read_u32::<LittleEndian>());
                    phdr.p_flags = try!(fd.read_u32::<LittleEndian>());
                    phdr.p_offset = try!(fd.read_u64::<LittleEndian>());
                    phdr.p_vaddr = try!(fd.read_u64::<LittleEndian>());
                    phdr.p_paddr = try!(fd.read_u64::<LittleEndian>());
                    phdr.p_filesz = try!(fd.read_u64::<LittleEndian>());
                    phdr.p_memsz = try!(fd.read_u64::<LittleEndian>());
                    phdr.p_align = try!(fd.read_u64::<LittleEndian>());
                } else {
                    phdr.p_type = try!(fd.read_u32::<BigEndian>());
                    phdr.p_flags = try!(fd.read_u32::<BigEndian>());
                    phdr.p_offset = try!(fd.read_u64::<BigEndian>());
                    phdr.p_vaddr = try!(fd.read_u64::<BigEndian>());
                    phdr.p_paddr = try!(fd.read_u64::<BigEndian>());
                    phdr.p_filesz = try!(fd.read_u64::<BigEndian>());
                    phdr.p_memsz = try!(fd.read_u64::<BigEndian>());
                    phdr.p_align = try!(fd.read_u64::<BigEndian>());
                }
                phdrs.push(phdr);
            }

            Ok(phdrs)
        }

        #[cfg(feature = "no_endian_fd")]
        pub fn from_fd(fd: &mut File, offset: u64, count: usize, _: bool) -> io::Result<Vec<ProgramHeader>> {
            use std::io::Read;
            let mut phdrs = vec![0u8; count * SIZEOF_PHDR];
            try!(fd.seek(Start(offset)));
            try!(fd.read(&mut phdrs));
            Ok(ProgramHeader::from_bytes(&phdrs, count))
        }
    }
}
