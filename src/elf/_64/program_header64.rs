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
        pub fn parse<S: scroll::Gread>(fd: &S, offset: u64, count: usize, little_endian: scroll::Endian) -> Result<Vec<ProgramHeader>> {
            let mut phdrs = vec![];
            let mut offset = offset as usize;
            for _ in 0..count {
                let mut phdr = ProgramHeader::default();
                phdr.p_type = try!(fd.gread(&mut offset, little_endian));
                phdr.p_flags = try!(fd.gread(&mut offset, little_endian));
                phdr.p_offset = try!(fd.gread(&mut offset, little_endian));
                phdr.p_vaddr = try!(fd.gread(&mut offset, little_endian));
                phdr.p_paddr = try!(fd.gread(&mut offset, little_endian));
                phdr.p_filesz = try!(fd.gread(&mut offset, little_endian));
                phdr.p_memsz = try!(fd.gread(&mut offset, little_endian));
                phdr.p_align = try!(fd.gread(&mut offset, little_endian));
                phdrs.push(phdr);
            }
            Ok(phdrs)
        }
    });
