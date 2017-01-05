pub use elf::section_header::*;

elf_section_header!(u64);

pub const SIZEOF_SHDR: usize = 64;

elf_section_header_impure_impl!(
    impl SectionHeader {
        elf_section_header_from_bytes!();
        elf_section_header_from_raw_parts!();
        elf_section_header_from_fd!();
        #[cfg(feature = "endian_fd")]
        pub fn parse<S: scroll::Gread>(fd: &S, offset: u64, count: usize, little_endian: scroll::Endian) -> Result<Vec<SectionHeader>> {
            let mut shdrs = Vec::with_capacity(count);
            let mut offset = offset as usize;
            for _ in 0..count {
                let mut shdr = SectionHeader::default();
                shdr.sh_name = try!(fd.gread(&mut offset, little_endian));
                shdr.sh_type = try!(fd.gread(&mut offset, little_endian));
                shdr.sh_flags = try!(fd.gread(&mut offset, little_endian));
                shdr.sh_addr = try!(fd.gread(&mut offset, little_endian));
                shdr.sh_offset = try!(fd.gread(&mut offset, little_endian));
                shdr.sh_size = try!(fd.gread(&mut offset, little_endian));
                shdr.sh_link = try!(fd.gread(&mut offset, little_endian));
                shdr.sh_info = try!(fd.gread(&mut offset, little_endian));
                shdr.sh_addralign = try!(fd.gread(&mut offset, little_endian));
                shdr.sh_entsize = try!(fd.gread(&mut offset, little_endian));
                shdrs.push(shdr);
            }
            Ok(shdrs)
        }
    });
