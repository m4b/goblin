use std::slice;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom::Start;
use std::io;

pub const PHDR_SIZE: usize = 64;

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_NUM: u32 = 8;
pub const PT_LOOS: u32 = 0x60000000;
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
pub const PT_GNU_STACK: u32 = 0x6474e551;
pub const PT_GNU_RELRO: u32 = 0x6474e552;
pub const PT_LOSUNW: u32 = 0x6ffffffa;
pub const PT_SUNWBSS: u32 = 0x6ffffffa;
pub const PT_SUNWSTACK: u32 = 0x6ffffffb;
pub const PT_HISUNW: u32 = 0x6fffffff;
pub const PT_HIOS: u32 = 0x6fffffff;
pub const PT_LOPROC: u32 = 0x70000000;
pub const PT_HIPROC: u32 = 0x7fffffff;

/// Segment is executable
pub const PF_X: u32 = 1 << 0;

/// Segment is writable
pub const PF_W: u32 = 1 << 1;

/// Segment is readable
pub const PF_R: u32 = 1 << 2;

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

fn pt_to_str(pt: u32) -> &'static str {
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
    pub fn from_bytes(bytes: Vec<u8>, phnum: usize) -> Vec<ProgramHeader> {
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

    pub fn from_fd(fd: &mut File, offset: u64, count: usize) -> io::Result<Vec<ProgramHeader>> {
        let mut phdrs: Vec<u8> = vec![0; count * PHDR_SIZE];
        try!(fd.seek(Start(offset)));
        try!(fd.read(&mut phdrs));
        Ok(ProgramHeader::from_bytes(phdrs, count))
    }
}
