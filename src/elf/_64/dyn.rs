pub use super::super::elf::dyn::*;

/// An entry in the dynamic array
#[repr(C)]
#[derive(Clone, PartialEq, Default)]
pub struct Dyn {
    pub d_tag: u64, // Dynamic entry type
    pub d_val: u64, // Integer value
}

pub const SIZEOF_DYN: usize = 16;

elf_dyn_impure_impl!(
    u64,
    pub fn from_fd(mut fd: &File, phdrs: &[ProgramHeader], is_lsb: bool) -> io::Result<Option<Vec<Dyn>>> {
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
