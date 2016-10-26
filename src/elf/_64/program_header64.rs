pub use elf::program_header::*;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Default)]
pub struct ProgramHeader {
    /// Segment type
    pub p_type: u32,
    /// Segment flags
    pub p_flags: u32,
    /// Segment file offset
    pub p_offset: u64,
    /// Segment virtual address
    pub p_vaddr: u64,
    /// Segment physical address
    pub p_paddr: u64,
    /// Segment size in file
    pub p_filesz: u64,
    /// Segment size in memory
    pub p_memsz: u64,
    /// Segment alignment
    pub p_align: u64,
}

pub const SIZEOF_PHDR: usize = 64;

elf_program_header_impure_impl!(
    impl ProgramHeader {
        elf_program_header_from_bytes!();
        elf_program_header_from_raw_parts!();
        elf_program_header_from_fd!();
        #[cfg(feature = "endian_fd")]
        pub fn parse<R: Read + Seek>(fd: &mut R, offset: u64, count: usize, is_lsb: bool) -> io::Result<Vec<ProgramHeader>> {
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
    });
