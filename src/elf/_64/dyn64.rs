pub use elf::dyn::*;

elf_dyn!(u64);

pub const SIZEOF_DYN: usize = 16;

elf_dyn_impure_impl!(
    u64,
    pub fn parse<R: Read + Seek> (mut fd: &mut R, phdrs: &[ProgramHeader], is_lsb: bool) -> io::Result<Option<Vec<Dyn>>> {
        use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
        for phdr in phdrs {
            if phdr.p_type == PT_DYNAMIC {
                let filesz = phdr.p_filesz as usize;
                let dync = filesz / SIZEOF_DYN;
                let mut dyns = Vec::with_capacity(dync);

                try!(fd.seek(Start(phdr.p_offset)));
                for _ in 0..dync {
                    let mut dyn = Dyn::default();

                    if is_lsb {
                        dyn.d_tag = try!(fd.read_u64::<LittleEndian>());
                        dyn.d_val = try!(fd.read_u64::<LittleEndian>());
                    } else {
                        dyn.d_tag = try!(fd.read_u64::<BigEndian>());
                        dyn.d_val = try!(fd.read_u64::<BigEndian>());
                    }

                    dyns.push(dyn);
                }

                dyns.dedup();
                return Ok(Some(dyns));
            }
        }
        Ok(None)
    });
