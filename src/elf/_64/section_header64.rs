pub use elf::section_header::*;

elf_section_header!(u64);

pub const SIZEOF_SHDR: usize = 64;

elf_section_header_impure_impl!(
    impl SectionHeader {
        elf_section_header_from_bytes!();
        elf_section_header_from_raw_parts!();
        elf_section_header_from_fd!();
        #[cfg(feature = "endian_fd")]
        pub fn parse<R: Read + Seek>(fd: &mut R, offset: u64, count: usize, is_lsb: bool) -> io::Result<Vec<SectionHeader>> {
            use byteorder::{LittleEndian,BigEndian,ReadBytesExt};

            let mut shdrs = Vec::with_capacity(count);
            try!(fd.seek(Start(offset)));

            for _ in 0..count {
                let mut shdr = SectionHeader::default();
                if is_lsb {
                    shdr.sh_name = try!(fd.read_u32::<LittleEndian>());
                    shdr.sh_type = try!(fd.read_u32::<LittleEndian>());
                    shdr.sh_flags = try!(fd.read_u64::<LittleEndian>());
                    shdr.sh_addr = try!(fd.read_u64::<LittleEndian>());
                    shdr.sh_offset = try!(fd.read_u64::<LittleEndian>());
                    shdr.sh_size = try!(fd.read_u64::<LittleEndian>());
                    shdr.sh_link = try!(fd.read_u32::<LittleEndian>());
                    shdr.sh_info = try!(fd.read_u32::<LittleEndian>());
                    shdr.sh_addralign = try!(fd.read_u64::<LittleEndian>());
                    shdr.sh_entsize = try!(fd.read_u64::<LittleEndian>());
                } else {
                    shdr.sh_name = try!(fd.read_u32::<BigEndian>());
                    shdr.sh_type = try!(fd.read_u32::<BigEndian>());
                    shdr.sh_flags = try!(fd.read_u64::<BigEndian>());
                    shdr.sh_addr = try!(fd.read_u64::<BigEndian>());
                    shdr.sh_offset = try!(fd.read_u64::<BigEndian>());
                    shdr.sh_size = try!(fd.read_u64::<BigEndian>());
                    shdr.sh_link = try!(fd.read_u32::<BigEndian>());
                    shdr.sh_info = try!(fd.read_u32::<BigEndian>());
                    shdr.sh_addralign = try!(fd.read_u64::<BigEndian>());
                    shdr.sh_entsize = try!(fd.read_u64::<BigEndian>());
                }
                shdrs.push(shdr);
            }
            Ok(shdrs)
        }
    });
