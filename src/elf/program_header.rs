#[cfg(feature = "std")]
pub trait ElfProgramHeader {
    fn p_type(&self) -> u32;
    fn p_flags(&self) -> u32;
    fn p_offset(&self) -> u64;
    fn p_vaddr(&self) -> u64;
    fn p_paddr(&self) -> u64;
    fn p_filesz(&self) -> u64;
    fn p_memsz(&self) -> u64;
    fn p_align(&self) -> u64;
}

/// Program header table entry unused
pub const PT_NULL: u32 = 0;
/// Loadable program segment
pub const PT_LOAD: u32 = 1;
/// Dynamic linking information
pub const PT_DYNAMIC: u32 = 2;
/// Program interpreter
pub const PT_INTERP: u32 = 3;
/// Auxiliary information
pub const PT_NOTE: u32 = 4;
/// Reserved
pub const PT_SHLIB: u32 = 5;
/// Entry for header table itself
pub const PT_PHDR: u32 = 6;
/// Thread-local storage segment
pub const PT_TLS: u32 = 7;
/// Number of defined types
pub const PT_NUM: u32 = 8;
/// Start of OS-specific
pub const PT_LOOS: u32 = 0x60000000;
/// GCC .eh_frame_hdr segment
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
/// Indicates stack executability
pub const PT_GNU_STACK: u32 = 0x6474e551;
/// Read-only after relocation
pub const PT_GNU_RELRO: u32 = 0x6474e552;
/// Sun Specific segment
pub const PT_LOSUNW: u32 = 0x6ffffffa;
/// Sun Specific segment
pub const PT_SUNWBSS: u32 = 0x6ffffffa;
/// Stack segment
pub const PT_SUNWSTACK: u32 = 0x6ffffffb;
/// End of OS-specific
pub const PT_HISUNW: u32 = 0x6fffffff;
/// End of OS-specific
pub const PT_HIOS: u32 = 0x6fffffff;
/// Start of processor-specific
pub const PT_LOPROC: u32 = 0x70000000;
/// End of processor-specific
pub const PT_HIPROC: u32 = 0x7fffffff;

/// Segment is executable
pub const PF_X: u32 = 1 << 0;

/// Segment is writable
pub const PF_W: u32 = 1 << 1;

/// Segment is readable
pub const PF_R: u32 = 1 << 2;

pub fn pt_to_str(pt: u32) -> &'static str {
    match pt {
        PT_NULL => "PT_NULL",
        PT_LOAD => "PT_LOAD",
        PT_DYNAMIC => "PT_DYNAMIC",
        PT_INTERP => "PT_INTERP",
        PT_NOTE => "PT_NOTE",
        PT_SHLIB => "PT_SHLIB",
        PT_PHDR => "PT_PHDR",
        PT_TLS => "PT_TLS",
        PT_NUM => "PT_NUM",
        PT_LOOS => "PT_LOOS",
        PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
        PT_GNU_STACK => "PT_GNU_STACK",
        PT_GNU_RELRO => "PT_GNU_RELRO",
        PT_SUNWBSS => "PT_SUNWBSS",
        PT_SUNWSTACK => "PT_SUNWSTACK",
        PT_HIOS => "PT_HIOS",
        PT_LOPROC => "PT_LOPROC",
        PT_HIPROC => "PT_HIPROC",
        _ => "UNKNOWN_PT",
    }
}

macro_rules! elf_program_header_from_bytes { () => {
        pub fn from_bytes(bytes: &[u8], phnum: usize) -> Vec<ProgramHeader> {
            let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut ProgramHeader, phnum) };
            let mut phdrs = Vec::with_capacity(phnum);
            phdrs.extend_from_slice(bytes);
            phdrs
        }};}

macro_rules! elf_program_header_from_raw_parts { () => {
        pub unsafe fn from_raw_parts<'a>(phdrp: *const ProgramHeader,
                                         phnum: usize)
                                         -> &'a [ProgramHeader] {
            slice::from_raw_parts(phdrp, phnum)
        }};}

macro_rules! elf_program_header_from_fd { () => {
        pub fn from_fd(fd: &mut File, offset: u64, count: usize) -> io::Result<Vec<ProgramHeader>> {
            let mut phdrs = vec![0u8; count * SIZEOF_PHDR];
            try!(fd.seek(Start(offset)));
            try!(fd.read(&mut phdrs));
            Ok(ProgramHeader::from_bytes(&phdrs, count))
        }
    };}

macro_rules! elf_program_header_from_endian { ($from_endian:item) => {
        #[cfg(feature = "endian_fd")]
        $from_endian
    };}

macro_rules! elf_program_header_impure_impl { ($header:item) => {

        #[cfg(feature = "std")]
        pub use self::impure::*;

        #[cfg(feature = "std")]
        mod impure {

            use super::*;

            use core::slice;
            use core::fmt;

            use std::fs::File;
            use std::io::{self, Seek, Read};
            use std::io::SeekFrom::Start;

            #[cfg(feature = "endian_fd")]
            impl ElfProgramHeader for ProgramHeader {
                fn p_type(&self) -> u32 {
                    self.p_type
                }
                fn p_flags(&self) -> u32 {
                    self.p_flags
                }
                fn p_offset(&self) -> u64 {
                    self.p_offset as u64
                }
                fn p_vaddr(&self) -> u64 {
                    self.p_vaddr as u64
                }
                fn p_paddr(&self) -> u64 {
                    self.p_paddr as u64
                }
                fn p_filesz(&self) -> u64 {
                    self.p_filesz as u64
                }
                fn p_memsz(&self) -> u64 {
                    self.p_memsz as u64
                }
                fn p_align(&self) -> u64 {
                    self.p_align as u64
                }
            }

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
            $header
        }
    };}
