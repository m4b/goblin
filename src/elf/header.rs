include!("constants_header.rs");

pub trait ElfHeader {
    fn e_ident(&self) -> [u8; SIZEOF_IDENT];
    fn e_type(&self) -> u16;
    fn e_machine(&self) -> u16;
    fn e_version(&self) -> u32;
    fn e_entry(&self) -> u64;
    fn e_phoff(&self) -> u64;
    fn e_shoff(&self) -> u64;
    fn e_flags(&self) -> u32;
    fn e_ehsize(&self) -> u16;
    fn e_phentsize(&self) -> u16;
    fn e_phnum(&self) -> u16;
    fn e_shentsize(&self) -> u16;
    fn e_shnum(&self) -> u16;
    fn e_shstrndx(&self) -> u16;
}

macro_rules! elf_header {
    ($size:ident) => {
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
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
/// SELF (Security-enhanced ELF) magic number.
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
        //let mut offset = &mut 0;
        let ident: &[u8] = buffer.pread_slice(0, SIZEOF_IDENT)?;
        if &ident[0..SELFMAG] != ELFMAG {
            return Err(Error::BadMagic(ident.pread_into(0)?).into());
        }
        let class = ident[EI_CLASS];
        let is_lsb = ident[EI_DATA] == ELFDATA2LSB;
        Ok((class, is_lsb))
    }
}

macro_rules! elf_header_test_peek {
    ($class:expr) => {
        #[cfg(test)]
        mod tests {
            use super::*;
            use std::io::Cursor;
            #[test]
            fn test_peek () {
                let v = vec![0x7f, 0x45, 0x4c, 0x46, $class, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x70, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x8c];
                let mut header = Cursor::new(v);
                match peek(&mut header) {
                    Err(_) => assert!(false),
                    Ok((class, is_lsb)) => {
                        assert_eq!(true, is_lsb);
                        assert_eq!(class, $class)
                    }
                }
            }
        }
    }
}

macro_rules! elf_header_impure_impl {
    ($size:expr) => {
        #[cfg(feature = "std")]
        pub use self::impure::*;

        #[cfg(feature = "std")]
        mod impure {

            use super::*;
            use elf::error::*;
            use elf::error;

            use core::fmt;
            use scroll;
            use std::fs::File;
            use std::io::{Read};

            impl ElfHeader for Header {
                fn e_ident(&self) -> [u8; SIZEOF_IDENT] {
                    self.e_ident
                }
                fn e_type(&self) -> u16 {
                    self.e_type
                }
                fn e_machine(&self) -> u16 {
                    self.e_machine
                }
                fn e_version(&self) -> u32 {
                    self.e_version
                }
                fn e_entry(&self) -> u64 {
                    self.e_entry as u64
                }
                fn e_phoff(&self) -> u64 {
                    self.e_phoff as u64
                }
                fn e_shoff(&self) -> u64 {
                    self.e_shoff as u64
                }
                fn e_flags(&self) -> u32 {
                    self.e_flags
                }
                fn e_ehsize(&self) -> u16 {
                    self.e_ehsize
                }
                fn e_phentsize(&self) -> u16 {
                    self.e_phentsize
                }
                fn e_phnum(&self) -> u16 {
                    self.e_phnum
                }
                fn e_shentsize(&self) -> u16 {
                    self.e_shentsize
                }
                fn e_shnum(&self) -> u16 {
                    self.e_shnum
                }
                fn e_shstrndx(&self) -> u16 {
                    self.e_shstrndx
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
                        elf_header.e_ident[i] = buffer.gread_into(&mut offset)?;
                    }
                    let endianness =
                        match elf_header.e_ident[EI_DATA] {
                            ELFDATA2LSB => scroll::LE,
                            ELFDATA2MSB => scroll::BE,
                            d => return Err(Error::Malformed(format!("invalid ELF DATA type {:x}", d)).into()),
                        };
                    elf_header.e_type =      buffer.gread(offset, endianness)?;
                    elf_header.e_machine =   buffer.gread(offset, endianness)?;
                    elf_header.e_version =   buffer.gread(offset, endianness)?;
                    elf_header.e_entry =     buffer.gread(offset, endianness)?;
                    elf_header.e_phoff =     buffer.gread(offset, endianness)?;
                    elf_header.e_shoff =     buffer.gread(offset, endianness)?;
                    elf_header.e_flags =     buffer.gread(offset, endianness)?;
                    elf_header.e_ehsize =    buffer.gread(offset, endianness)?;
                    elf_header.e_phentsize = buffer.gread(offset, endianness)?;
                    elf_header.e_phnum =     buffer.gread(offset, endianness)?;
                    elf_header.e_shentsize = buffer.gread(offset, endianness)?;
                    elf_header.e_shnum =     buffer.gread(offset, endianness)?;
                    elf_header.e_shstrndx =  buffer.gread(offset, endianness)?;
                    Ok(elf_header)
                }
            }
        }
    };
}
