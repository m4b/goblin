include!("constants_header.rs");

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
        ELFCLASS32 => "ELF64",
        ELFCLASS64 => "ELF32",
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

#[cfg(not(feature = "pure"))]
pub use self::impure::*;

    #[cfg(not(feature = "pure"))]
mod impure {
    use super::*;

    use std::io;
    use std::io::{Seek, Read};
    use std::io::SeekFrom::Start;

    /// Peek at important data in an ELF byte stream, and return the ELF class and endianness if it's a valid stream
    pub fn peek<R: Read + Seek>(fd: &mut R) -> io::Result<(u8, bool)> {
        let mut ident = [0u8; SIZEOF_IDENT];
        try!(fd.seek(Start(0)));

        match try!(fd.read(&mut ident)) {
            SIZEOF_IDENT => {

                if &ident[0..SELFMAG] != ELFMAG {
                    return io_error!("Invalid ELF magic number: {:?}", &ident[0..SELFMAG]);
                }

                let class = ident[EI_CLASS];
                let is_lsb = ident[EI_DATA] == ELFDATA2LSB;
                Ok((class, is_lsb))
            }
            count => {
                io_error!("Error: {:?} size is smaller than an ELF identication header",
                          count)
            }
        }
    }
}

/// Derive the `from_bytes` method for a header.
macro_rules! elf_header_from_bytes {
        () => {
            /// Returns the corresponding ELF header from the given byte array.
            pub fn from_bytes(bytes: &[u8; SIZEOF_EHDR]) -> &Header {
                // This is not unsafe because the header's size is encoded in the function,
                // although the header can be semantically invalid.
                let header: &Header = unsafe { mem::transmute(bytes) };
                header
            }
        };
    }

/// Derive the `from_fd` method for a header.
macro_rules! elf_header_from_fd {
        () => {
            /// Load a header from a file.
            #[cfg(feature = "no_endian_fd")]
            pub fn from_fd(fd: &mut File) -> io::Result<Header> {
                let mut elf_header = [0; SIZEOF_EHDR];
                try!(fd.read(&mut elf_header));
                Ok(*Header::from_bytes(&elf_header))
            }
        };
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
        ($header:item) => {
            #[cfg(not(feature = "pure"))]
            pub use self::impure::*;

            #[cfg(not(feature = "pure"))]
            mod impure {

                use super::*;

                use std::mem;
                use std::fmt;
                use std::fs::File;
                use std::io::Read;
                use std::io;

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

                $header
            }
        };
    }
