include!("constants_header.rs");

use error::{self};
use scroll::{self, ctx};
use core::fmt;

#[derive(Clone, PartialEq)]
pub struct ElfHeader {
    pub e_ident           : [u8; SIZEOF_IDENT],
    pub e_type            : u16,
    pub e_machine         : u16,
    pub e_version         : u32,
    pub e_entry           : u64,
    pub e_phoff           : u64,
    pub e_shoff           : u64,
    pub e_flags           : u32,
    pub e_ehsize          : u16,
    pub e_phentsize       : u16,
    pub e_phnum           : u16,
    pub e_shentsize       : u16,
    pub e_shnum           : u16,
    pub e_shstrndx        : u16,
}

impl ElfHeader {
    pub fn new(machine: super::super::Machine) -> Self {
        use super::super::Machine::*;
        let (typ, ehsize, phentsize, shentsize) = match machine {
            M32 => {
                (ELFCLASS32, super::super::elf32::header::SIZEOF_EHDR,
                 super::super::elf32::program_header::SIZEOF_PHDR,
                 super::super::elf32::section_header::SIZEOF_SHDR)
            },
            M64 => {
                (ELFCLASS64, super::super::elf64::header::SIZEOF_EHDR,
                 super::super::elf64::program_header::SIZEOF_PHDR,
                 super::super::elf64::section_header::SIZEOF_SHDR)
            }
        };
        ElfHeader {
            e_ident: [
                127,
                69,
                76,
                70,
                typ,
                ELFDATANONE,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ],
            e_type: ET_DYN,
            e_machine: EM_NONE,
            e_version: 1,
            e_entry: 0x0,
            e_phoff: 0x0,
            e_shoff: 0x0,
            e_flags: 0,
            e_ehsize: ehsize as u16,
            e_phentsize: phentsize as u16,
            e_phnum: 0,
            e_shentsize: shentsize as u16,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }
}

impl fmt::Debug for ElfHeader {
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

impl<'a> ctx::TryFromCtx<'a> for ElfHeader {
    type Error = error::Error;
    fn try_from_ctx(buffer: &'a [u8], (offset, _): (usize, scroll::Endian)) -> error::Result<Self> {
        use scroll::{Pread};
        use error::Error;
        let ident: &[u8] = buffer.pread_slice(offset, SIZEOF_IDENT)?;
        if &ident[0..SELFMAG] != ELFMAG {
            let magic: u64 = ident.pread_with(offset, scroll::LE)?;
            return Err(Error::BadMagic(magic).into());
        }
        let class = ident[EI_CLASS];
        match class {
            ELFCLASS32 => {
                Ok(ElfHeader::from(buffer.pread::<super::super::elf32::header::Header>(offset)?))
            },
            ELFCLASS64 => {
                Ok(ElfHeader::from(buffer.pread::<super::super::elf64::header::Header>(offset)?))
            },
            _ => {
                return Err(Error::Malformed(format!("invalid ELF class {:x}", class)).into())
            }
        }
    }
}

macro_rules! elf_header {
    ($size:ident) => {
        use core::fmt;

        #[repr(C)]
        #[derive(Clone, Copy, Default, PartialEq)]
        pub struct Header {
            /// Magic number and other info
            pub e_ident: [u8; SIZEOF_IDENT],
            /// Object file type
            pub e_type: u16,
            /// Architecture
            pub e_machine: u16,
            /// Object file version
            pub e_version: u32,
            /// Entry point virtual address
            pub e_entry: $size,
            /// Program header table file offset
            pub e_phoff: $size,
            /// Section header table file offset
            pub e_shoff: $size,
            /// Processor-specific flags
            pub e_flags: u32,
            /// ELF header size in bytes
            pub e_ehsize: u16,
            /// Program header table entry size
            pub e_phentsize: u16,
            /// Program header table entry count
            pub e_phnum: u16,
            /// Section header table entry size
            pub e_shentsize: u16,
            /// Section header table entry count
            pub e_shnum: u16,
            /// Section header string table index
            pub e_shstrndx: u16,
        }
        impl Header {
            /// Returns the corresponding ELF header from the given byte array.
            pub fn from_bytes(bytes: &[u8; SIZEOF_EHDR]) -> &Header {
                // This is not unsafe because the header's size is encoded in the function,
                // although the header can be semantically invalid.
                let header: &Header = unsafe { ::core::mem::transmute(bytes) };
                header
            }
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
    }
}

/// No file type.
pub const ET_NONE: u16 = 0;
/// Relocatable file.
pub const ET_REL: u16 = 1;
/// Executable file.
pub const ET_EXEC: u16 = 2;
/// Shared object file.
pub const ET_DYN: u16 = 3;
/// Core file.
pub const ET_CORE: u16 = 4;
/// Number of defined types.
pub const ET_NUM: u16 = 5;

/// The ELF magic number.
pub const ELFMAG: &'static [u8; 4] = b"\x7FELF";
/// Sizeof ELF magic number.
pub const SELFMAG: usize = 4;

/// File class byte index.
pub const EI_CLASS: usize = 4;
/// Invalid class.
pub const ELFCLASSNONE: u8 = 0;
/// 32-bit objects.
pub const ELFCLASS32: u8 = 1;
/// 64-bit objects.
pub const ELFCLASS64: u8 = 2;
/// ELF class number.
pub const ELFCLASSNUM: u8 = 3;

/// Data encoding byte index.
pub const EI_DATA: usize = 5;
/// Invalid data encoding.
pub const ELFDATANONE: u8 = 0;
/// 2's complement, little endian.
pub const ELFDATA2LSB: u8 = 1;
/// 2's complement, big endian.
pub const ELFDATA2MSB: u8 = 2;
/// Number of bytes in an identifier.
pub const SIZEOF_IDENT: usize = 16;

/// Convert a ELF class byte to the associated string.
#[inline]
pub fn class_to_str(et: u8) -> &'static str {
    match et {
        ELFCLASSNONE => "NONE",
        ELFCLASS32 => "ELF32",
        ELFCLASS64 => "ELF64",
        _ => "UNKNOWN_CLASS",
    }
}

/// Convert an ET value to their associated string.
#[inline]
pub fn et_to_str(et: u16) -> &'static str {
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

#[cfg(feature = "std")]
pub use self::impure::*;

#[cfg(feature = "std")]
mod impure {
    use super::*;

    use scroll::{self, Pread};
    use elf::error::*;

    /// Peek at important data in an ELF byte stream, and return the ELF class and endianness
    /// if it's a valid byte sequence
    pub fn peek<S: scroll::Pread>(buffer: &S) -> Result<(u8, bool)> {
        let ident: &[u8] = buffer.pread_slice(0, SIZEOF_IDENT)?;
        if &ident[0..SELFMAG] != ELFMAG {
            let magic: u64 = ident.pread_with(0, scroll::LE)?;
            return Err(Error::BadMagic(magic).into());
        }
        let class = ident[EI_CLASS];
        let is_lsb = ident[EI_DATA] == ELFDATA2LSB;
        Ok((class, is_lsb))
    }
}

macro_rules! elf_header_impure_impl {
    ($size:expr, $width:ty) => {
        #[cfg(feature = "std")]
        pub use self::impure::*;

        #[cfg(feature = "std")]
        mod impure {

            use super::*;
            use elf::error::*;
            use elf::error;

            use scroll::{self, ctx};
            use std::fs::File;
            use std::io::{Read};

            use core::result;

            impl From<ElfHeader> for Header {
                fn from(eh: ElfHeader) -> Self {
                    Header {
                        e_ident: eh.e_ident,
                        e_type: eh.e_type,
                        e_machine: eh.e_machine,
                        e_version: eh.e_version,
                        e_entry: eh.e_entry as $width,
                        e_phoff: eh.e_phoff as $width,
                        e_shoff: eh.e_shoff as $width,
                        e_flags: eh.e_flags,
                        e_ehsize: eh.e_ehsize,
                        e_phentsize: eh.e_phentsize,
                        e_phnum: eh.e_phnum,
                        e_shentsize: eh.e_shentsize,
                        e_shnum: eh.e_shnum,
                        e_shstrndx: eh.e_shstrndx,
                    }
                }
            }

            impl From<Header> for ElfHeader {
                fn from(eh: Header) -> Self {
                    ElfHeader {
                        e_ident: eh.e_ident,
                        e_type: eh.e_type,
                        e_machine: eh.e_machine,
                        e_version: eh.e_version,
                        e_entry: eh.e_entry as u64,
                        e_phoff: eh.e_phoff as u64,
                        e_shoff: eh.e_shoff as u64,
                        e_flags: eh.e_flags,
                        e_ehsize: eh.e_ehsize,
                        e_phentsize: eh.e_phentsize,
                        e_phnum: eh.e_phnum,
                        e_shentsize: eh.e_shentsize,
                        e_shnum: eh.e_shnum,
                        e_shstrndx: eh.e_shstrndx,
                    }
                }
            }

            impl<'a> ctx::TryFromCtx<'a> for Header {
                type Error = error::Error;
                fn try_from_ctx(buffer: &'a [u8], (mut offset, _): (usize, scroll::Endian)) -> result::Result<Self, Self::Error> {
                    use scroll::Gread;
                    let mut elf_header = Header::default();
                    let mut offset = &mut offset;
                    buffer.gread_inout(offset, &mut elf_header.e_ident)?;
                    let endianness =
                        match elf_header.e_ident[EI_DATA] {
                            ELFDATA2LSB => scroll::LE,
                            ELFDATA2MSB => scroll::BE,
                            d => return Err(Error::Malformed(format!("invalid ELF endianness DATA type {:x}", d)).into()),
                        };
                    elf_header.e_type =      buffer.gread_with(offset, endianness)?;
                    elf_header.e_machine =   buffer.gread_with(offset, endianness)?;
                    elf_header.e_version =   buffer.gread_with(offset, endianness)?;
                    elf_header.e_entry =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_phoff =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_shoff =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_flags =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_ehsize =    buffer.gread_with(offset, endianness)?;
                    elf_header.e_phentsize = buffer.gread_with(offset, endianness)?;
                    elf_header.e_phnum =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_shentsize = buffer.gread_with(offset, endianness)?;
                    elf_header.e_shnum =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_shstrndx =  buffer.gread_with(offset, endianness)?;
                    Ok(elf_header)
                }
            }

            impl ctx::TryIntoCtx for Header {
                type Error = scroll::Error;
                /// a Pwrite impl for Header: **note** we use the endianness value in the header, and not a parameter
                fn try_into_ctx(self, mut bytes: &mut [u8], (mut offset, _endianness): (usize, scroll::Endian)) -> result::Result<(), Self::Error> {
                    use scroll::{Gwrite};
                    let mut offset = &mut offset;
                    let endianness =
                        match self.e_ident[EI_DATA] {
                            ELFDATA2LSB => scroll::LE,
                            ELFDATA2MSB => scroll::BE,
                            d => return Err(scroll::Error::BadInput(format!("invalid ELF endianness DATA type {:x}", d)).into()),
                        };
                    for i in 0..self.e_ident.len() {
                        bytes.gwrite(self.e_ident[i], offset)?;
                    }
                    bytes.gwrite_with(self.e_type      , offset, endianness)?;
                    bytes.gwrite_with(self.e_machine   , offset, endianness)?;
                    bytes.gwrite_with(self.e_version   , offset, endianness)?;
                    bytes.gwrite_with(self.e_entry     , offset, endianness)?;
                    bytes.gwrite_with(self.e_phoff     , offset, endianness)?;
                    bytes.gwrite_with(self.e_shoff     , offset, endianness)?;
                    bytes.gwrite_with(self.e_flags     , offset, endianness)?;
                    bytes.gwrite_with(self.e_ehsize    , offset, endianness)?;
                    bytes.gwrite_with(self.e_phentsize , offset, endianness)?;
                    bytes.gwrite_with(self.e_phnum     , offset, endianness)?;
                    bytes.gwrite_with(self.e_shentsize , offset, endianness)?;
                    bytes.gwrite_with(self.e_shnum     , offset, endianness)?;
                    bytes.gwrite_with(self.e_shstrndx  , offset, endianness)
                }
            }

            impl Header {

                /// Load a header from a file. **You must** ensure the seek is at the correct position.
                pub fn from_fd(buffer: &mut File) -> Result<Header> {
                    let mut elf_header = [0; $size];
                    buffer.read(&mut elf_header)?;
                    Ok(*Header::from_bytes(&elf_header))
                }

                #[cfg(feature = "endian_fd")]
                /// Parses an ELF header from the given buffer
                pub fn parse<S: scroll::Gread>(buffer: &S) -> Result<Header> {
                    let mut elf_header = Header::default();
                    let mut offset = &mut 0;
                    for i in 0..SIZEOF_IDENT {
                        elf_header.e_ident[i] = buffer.gread(&mut offset)?;
                    }
                    let endianness =
                        match elf_header.e_ident[EI_DATA] {
                            ELFDATA2LSB => scroll::LE,
                            ELFDATA2MSB => scroll::BE,
                            d => return Err(Error::Malformed(format!("invalid ELF DATA type {:x}", d)).into()),
                        };
                    elf_header.e_type =      buffer.gread_with(offset, endianness)?;
                    elf_header.e_machine =   buffer.gread_with(offset, endianness)?;
                    elf_header.e_version =   buffer.gread_with(offset, endianness)?;
                    elf_header.e_entry =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_phoff =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_shoff =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_flags =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_ehsize =    buffer.gread_with(offset, endianness)?;
                    elf_header.e_phentsize = buffer.gread_with(offset, endianness)?;
                    elf_header.e_phnum =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_shentsize = buffer.gread_with(offset, endianness)?;
                    elf_header.e_shnum =     buffer.gread_with(offset, endianness)?;
                    elf_header.e_shstrndx =  buffer.gread_with(offset, endianness)?;
                    Ok(elf_header)
                }
            }
        }
    };
}

// tests

macro_rules! elf_header_test {
    ($class:expr) => {
        #[cfg(test)]
        mod test {
            extern crate scroll;
            use scroll::{Pwrite, Pread};
            use super::*;
            use scroll::Buffer;
            #[test]
            fn test_peek () {
                let v = vec![0x7f, 0x45, 0x4c, 0x46, $class, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x70, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x8c];
                let header = Buffer::new(v);
                match peek(&header) {
                    Err(_) => assert!(false),
                    Ok((class, is_lsb)) => {
                        assert_eq!(true, is_lsb);
                        assert_eq!(class, $class)
                    }
                }
            }

            #[test]
            fn header_read_write () {
                let crt1: Vec<u8> =
                    if $class == ELFCLASS64 {
                        include!("../../../etc/crt1.rs")
                    } else {
                        include!("../../../etc/crt132.rs")
                    };
                let header: Header = crt1.pread(0).unwrap();
                assert_eq!(header.e_type, ET_REL);
                println!("header: {:?}", &header);
                let mut bytes = [0u8; SIZEOF_EHDR];
                bytes.pwrite(header, 0).unwrap();
                let header2: Header = bytes.pread(0).unwrap();
                assert_eq!(header, header2);
            }
            #[test]
            fn elfheader_read_write () {
                let (machine, crt1): (super::super::super::Machine, Vec<u8>) =
                    if $class == ELFCLASS64 {
                        (super::super::super::Machine::M64, include!("../../../etc/crt1.rs"))
                    } else {
                        (super::super::super::Machine::M32, include!("../../../etc/crt132.rs"))
                    };
                let header: ElfHeader = crt1.pread(0).unwrap();
                assert_eq!(header.e_type, ET_REL);
                println!("header: {:?}", &header);
                let mut bytes = [0u8; SIZEOF_EHDR];
                let header_ = Header::from(header.clone());
                bytes.pwrite(header_, 0).unwrap();
                let header2: ElfHeader = bytes.pread(0).unwrap();
                assert_eq!(header, header2);
                let header= ElfHeader::new(machine);
                println!("header: {:?}", &header);
                //assert!(false);
            }
        }
    }
}
