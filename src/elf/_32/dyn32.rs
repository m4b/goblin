pub use elf::dyn::*;

elf_dyn!(u32);

pub const SIZEOF_DYN: usize = 8;

elf_dyn_impure_impl!(
    u32,
    pub fn parse<S: scroll::Scroll> (fd: &S, phdrs: &[ProgramHeader], little_endian: bool) -> io::Result<Option<Vec<Dyn>>> {
        for phdr in phdrs {
            if phdr.p_type == PT_DYNAMIC {
                let filesz = phdr.p_filesz as usize;
                let dync = filesz / SIZEOF_DYN;
                let mut dyns = Vec::with_capacity(dync);
                let mut offset = phdr.p_offset as usize;
                for _ in 0..dync {
                    let mut dyn = Dyn::default();
                    dyn.d_tag = try!(fd.read_u32(&mut offset, little_endian));
                    dyn.d_val = try!(fd.read_u32(&mut offset, little_endian));
                    dyns.push(dyn);
                }
                return Ok(Some(dyns));
            }
        }
        Ok(None)
    });
