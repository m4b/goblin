pub use super::super::elf::dyn::*;

#[derive(Copy, Clone, PartialEq, Default)]
pub struct Dyn {
    pub d_tag: u32, // Dynamic entry type
    pub d_val: u32, // Integer value
}

pub const SIZEOF_DYN: usize = 8;

elf_dyn_impure_impl!(
    u32,
    pub fn from_fd(mut fd: &File, phdrs: &[ProgramHeader], is_lsb: bool) -> io::Result<Option<Vec<Dyn>>> {
        use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
        for phdr in phdrs {
            if phdr.p_type == PT_DYNAMIC {
                let filesz = phdr.p_filesz as usize;
                let dync = filesz / SIZEOF_DYN;
                let mut dyns = Vec::with_capacity(dync);

                try!(fd.seek(Start(phdr.p_offset as u64)));
                for _ in 0..dync {
                    let mut dyn = Dyn::default();

                    if is_lsb {
                        dyn.d_tag = try!(fd.read_u32::<LittleEndian>());
                        dyn.d_val = try!(fd.read_u32::<LittleEndian>());
                    } else {
                        dyn.d_tag = try!(fd.read_u32::<BigEndian>());
                        dyn.d_val = try!(fd.read_u32::<BigEndian>());
                    }

                    dyns.push(dyn);
                }

                dyns.dedup();
                return Ok(Some(dyns));
            }
        }
        Ok(None)
    });
