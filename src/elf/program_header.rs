use core::fmt;
use scroll::{self, ctx, Gread};
use error;
use core::result;
use container::{Ctx, Container};

#[cfg(feature = "std")]
#[derive(Default, PartialEq, Clone)]
pub struct ElfProgramHeader {
    pub p_type  : u32,
    pub p_flags : u32,
    pub p_offset: u64,
    pub p_vaddr : u64,
    pub p_paddr : u64,
    pub p_filesz: u64,
    pub p_memsz : u64,
    pub p_align : u64,
}

impl ElfProgramHeader {
    /// Return the size of the underlying program header, given a `Ctx`
    #[inline]
    pub fn size(ctx: &Ctx) -> usize {
        use scroll::ctx::SizeWith;
        Self::size_with(&ctx)
    }
    /// Create a new X+R, `PT_LOAD` ELF program header
    pub fn new() -> Self {
        ElfProgramHeader {
            p_type  : PT_LOAD,
            p_flags : PF_X | PF_R,
            p_offset: 0,
            p_vaddr : 0,
            p_paddr : 0,
            p_filesz: 0,
            p_memsz : 0,
            p_align : 2 << 8,
        }
    }
    #[cfg(feature = "endian_fd")]
    pub fn parse<S: AsRef<[u8]>>(buffer: &S, mut offset: usize, count: usize, ctx: Ctx) -> error::Result<Vec<ElfProgramHeader>> {
        let mut program_headers = Vec::with_capacity(count);
        for _ in 0..count {
            let phdr = buffer.gread_with(&mut offset, ctx)?;
            program_headers.push(phdr);
        }
        Ok(program_headers)
    }
}

impl fmt::Debug for ElfProgramHeader {
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

impl ctx::SizeWith<Ctx> for ElfProgramHeader {
    type Units = usize;
    fn size_with(ctx: &Ctx) -> usize {
        match ctx.container {
            Container::Little => {
                super::super::elf32::program_header::SIZEOF_PHDR
            },
            Container::Big => {
                super::super::elf64::program_header::SIZEOF_PHDR
            },
        }
    }
}

impl<'a> ctx::TryFromCtx<'a, (usize, Ctx)> for ElfProgramHeader {
    type Error = scroll::Error;
    fn try_from_ctx(buffer: &'a [u8], (offset, Ctx { container, le}): (usize, Ctx)) -> result::Result<Self, Self::Error> {
        use scroll::Pread;
        let phdr = match container {
            Container::Little => {
                buffer.pread_with::<super::super::elf32::program_header::ProgramHeader>(offset, le)?.into()
            },
            Container::Big => {
                buffer.pread_with::<super::super::elf64::program_header::ProgramHeader>(offset, le)?.into()
            }
        };
        Ok(phdr)
    }
}

impl ctx::TryIntoCtx<(usize, Ctx)> for ElfProgramHeader {
    type Error = scroll::Error;
    fn try_into_ctx(self, mut buffer: &mut [u8], (offset, Ctx {container, le}): (usize, Ctx)) -> result::Result<(), Self::Error> {
        use scroll::Pwrite;
        match container {
            Container::Little => {
                let phdr: super::super::elf32::program_header::ProgramHeader = self.into();
                buffer.pwrite_with(phdr, offset, le)?;
            },
            Container::Big => {
                let phdr: super::super::elf64::program_header::ProgramHeader = self.into();
                buffer.pwrite_with(phdr, offset, le)?;
            }
        }
        Ok(())
    }
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
/// ARM unwind segment
pub const PT_ARM_EXIDX: u32 = 0x70000001;
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
        PT_ARM_EXIDX => "PT_ARM_EXIDX",
        _ => "UNKNOWN_PT",
    }
}

macro_rules! elf_program_header_impure_impl { ($size:ty) => {

    #[cfg(test)]
    mod test {
        use super::*;
        #[test]
        fn size_of() {
            assert_eq!(::std::mem::size_of::<ProgramHeader>(), SIZEOF_PHDR);
        }
    }

    #[cfg(feature = "std")]
    pub use self::impure::*;

    #[cfg(feature = "std")]
    mod impure {

        use super::*;
        use elf::error::*;

        use core::slice;
        use core::fmt;

        use scroll;
        use std::fs::File;
        use std::io::{Seek, Read};
        use std::io::SeekFrom::Start;

        impl From<ProgramHeader> for ElfProgramHeader {
            fn from(ph: ProgramHeader) -> Self {
                ElfProgramHeader {
                    p_type   : ph.p_type,
                    p_flags  : ph.p_flags,
                    p_offset : ph.p_offset as u64,
                    p_vaddr  : ph.p_vaddr as u64,
                    p_paddr  : ph.p_paddr as u64,
                    p_filesz : ph.p_filesz as u64,
                    p_memsz  : ph.p_memsz as u64,
                    p_align  : ph.p_align as u64,
                }
            }
        }

        impl From<ElfProgramHeader> for ProgramHeader {
            fn from(ph: ElfProgramHeader) -> Self {
                ProgramHeader {
                    p_type   : ph.p_type,
                    p_flags  : ph.p_flags,
                    p_offset : ph.p_offset as $size,
                    p_vaddr  : ph.p_vaddr  as $size,
                    p_paddr  : ph.p_paddr  as $size,
                    p_filesz : ph.p_filesz as $size,
                    p_memsz  : ph.p_memsz  as $size,
                    p_align  : ph.p_align  as $size,
                }
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
            #[cfg(feature = "endian_fd")]
            pub fn parse<S: scroll::Gread>(buffer: &S, mut offset: usize, count: usize, ctx: scroll::Endian) -> Result<Vec<ProgramHeader>> {
                let mut program_headers = vec![ProgramHeader::default(); count];
                let mut offset = &mut offset;
                buffer.gread_inout_with(offset, &mut program_headers, ctx)?;
                Ok(program_headers)
            }


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

            pub fn from_fd(fd: &mut File, offset: u64, count: usize) -> Result<Vec<ProgramHeader>> {
                let mut phdrs = vec![0u8; count * SIZEOF_PHDR];
                try!(fd.seek(Start(offset)));
                try!(fd.read(&mut phdrs));
                Ok(ProgramHeader::from_bytes(&phdrs, count))
            }
        }
    }
};}
