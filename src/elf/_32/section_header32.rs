pub use elf::section_header::*;

elf_section_header!(u32);

pub const SIZEOF_SHDR: usize = 40;

elf_section_header_impure_impl!(
    impl SectionHeader {
        elf_section_header_from_bytes!();
        elf_section_header_from_raw_parts!();
        elf_section_header_from_fd!();
        #[cfg(feature = "endian_fd")]
        pub fn parse<S: scroll::Gread>(fd: &S, offset: u64, count: usize, little_endian: scroll::Endian) -> Result<Vec<SectionHeader>> {
            let mut shdrs = Vec::with_capacity(count);
            let mut offset = &mut (offset as usize);
            for _ in 0..count {
                let mut shdr = SectionHeader::default();
                shdr.sh_name =      fd.gread(offset, little_endian)?;
                shdr.sh_type =      fd.gread(offset, little_endian)?;
                shdr.sh_flags =     fd.gread(offset, little_endian)?;
                shdr.sh_addr =      fd.gread(offset, little_endian)?;
                shdr.sh_offset =    fd.gread(offset, little_endian)?;
                shdr.sh_size =      fd.gread(offset, little_endian)?;
                shdr.sh_link =      fd.gread(offset, little_endian)?;
                shdr.sh_info =      fd.gread(offset, little_endian)?;
                shdr.sh_addralign = fd.gread(offset, little_endian)?;
                shdr.sh_entsize =   fd.gread(offset, little_endian)?;
                shdrs.push(shdr);
            }
            Ok(shdrs)
        }
    });
