pub use elf::rela::*;

// Stupid 32 bit binaries have Rel too, because 4 extra bytes for every relocation for an addend of 0 was prohibitive back in 1906.
// I think 32-bit binaries are stupid relics from the past in case that wasn't clear
#[repr(C)]
#[derive(Clone, PartialEq, Default)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Rel {
    /// address
    pub r_offset: u32,
    /// relocation type and symbol address
    pub r_info: u32,
}

elf_rela!(u32, i32);

pub const SIZEOF_RELA: usize = 4 + 4 + 4;

#[inline(always)]
pub fn r_sym(info: u32) -> u32 {
    info >> 8
}

#[inline(always)]
pub fn r_type(info: u32) -> u32 {
    info & 0xff
}

#[inline(always)]
pub fn r_info(sym: u32, typ: u32) -> u32 {
    (sym << 8) + (typ & 0xff)
}

elf_rela_impure_impl!(
    pub fn parse<R: Read + Seek>(fd: &mut R, offset: usize, size: usize, is_lsb: bool) -> io::Result<Vec<Rela>> {
        use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
        let count = size / SIZEOF_RELA;
        let mut res = Vec::with_capacity(count);

        try!(fd.seek(Start(offset as u64)));
        for _ in 0..count {
            let mut rela = Rela::default();

            if is_lsb {
                rela.r_offset = try!(fd.read_u32::<LittleEndian>());
                rela.r_info = try!(fd.read_u32::<LittleEndian>());
                rela.r_addend = try!(fd.read_i32::<LittleEndian>());
            } else {
                rela.r_offset = try!(fd.read_u32::<BigEndian>());
                rela.r_info = try!(fd.read_u32::<BigEndian>());
                rela.r_addend = try!(fd.read_i32::<BigEndian>());
            }

            res.push(rela);
        }

        res.dedup();
        Ok(res)
    });
