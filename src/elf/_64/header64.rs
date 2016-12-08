pub use elf::header::*;

elf_header!(u64);

pub const SIZEOF_EHDR: usize = 64;
pub const ELFCLASS: u8 = ELFCLASS64;

elf_header_impure_impl!(
    impl Header {
        elf_header_from_bytes!();
        elf_header_from_fd!();
        #[cfg(feature = "endian_fd")]
        /// Parses an ELF header from the given buffer
        pub fn parse<S: scroll::Scroll<usize>>(buffer: &S) -> io::Result<Header> {
            let mut elf_header = Header::default();
            let mut offset = 0;
            // maybe should just add a byte_slice method on scroll
            // elf_header.e_ident = buffer.slice([0, SIZEOF_IDENT]);
            for i in 0..SIZEOF_IDENT {
                elf_header.e_ident[i] = try!(buffer.read_u8(&mut offset));
            }
            let little_endian =
                match elf_header.e_ident[EI_DATA] {
                    ELFDATA2LSB => true,
                    ELFDATA2MSB => false,
                    d => return io_error!("Invalid ELF DATA type {:x}", d),
                };
            elf_header.e_type = try!(buffer.read_u16(&mut offset, little_endian));
            elf_header.e_machine = try!(buffer.read_u16(&mut offset, little_endian));
            elf_header.e_version = try!(buffer.read_u32(&mut offset, little_endian));
            elf_header.e_entry = try!(buffer.read_u64(&mut offset, little_endian));
            elf_header.e_phoff = try!(buffer.read_u64(&mut offset, little_endian));
            elf_header.e_shoff = try!(buffer.read_u64(&mut offset, little_endian));
            elf_header.e_flags = try!(buffer.read_u32(&mut offset, little_endian));
            elf_header.e_ehsize = try!(buffer.read_u16(&mut offset, little_endian));
            elf_header.e_phentsize = try!(buffer.read_u16(&mut offset, little_endian));
            elf_header.e_phnum = try!(buffer.read_u16(&mut offset, little_endian));
            elf_header.e_shentsize = try!(buffer.read_u16(&mut offset, little_endian));
            elf_header.e_shnum = try!(buffer.read_u16(&mut offset, little_endian));
            elf_header.e_shstrndx = try!(buffer.read_u16(&mut offset, little_endian));
            Ok(elf_header)
        }
    });

elf_header_test_peek!(ELFCLASS);
