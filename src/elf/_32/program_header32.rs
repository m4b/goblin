pub use elf::program_header::*;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Default)]
#[cfg_attr(feature = "endian_fd", derive(Pread, Pwrite))]
pub struct ProgramHeader {
    /// Segment type
    pub p_type: u32,
    /// Segment file offset
    pub p_offset: u32,
    /// Segment virtual address
    pub p_vaddr: u32,
    /// Segment physical address
    pub p_paddr: u32,
    /// Segment size in file
    pub p_filesz: u32,
    /// Segment size in memory
    pub p_memsz: u32,
    /// Segment flags
    pub p_flags: u32,
    /// Segment alignment
    pub p_align: u32,
}

pub const SIZEOF_PHDR: usize = 32;

elf_program_header_impure_impl!(u32);
