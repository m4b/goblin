/// TODO: add markdown columns
/// Relocation computations
/// R_X86_64_NONE 0 none none
/// R_X86_64_64 1 word64 S + A
/// R_X86_64_PC32 2 word32 S + A - P
/// R_X86_64_GOT32 3 word32 G + A
/// R_X86_64_PLT32 4 word32 L + A - P
/// R_X86_64_COPY 5 none none
/// R_X86_64_GLOB_DAT 6 word64 S
/// R_X86_64_JUMP_SLOT 7 word64 S
/// R_X86_64_RELATIVE 8 word64 B + A
/// R_X86_64_GOTPCREL 9 word32 G + GOT + A - P
/// R_X86_64_32 10 word32 S + A
/// R_X86_64_32S 11 word32 S + A
/// R_X86_64_16 12 word16 S + A
/// R_X86_64_PC16 13 word16 S + A - P
/// R_X86_64_8 14 word8 S + A
/// R_X86_64_PC8 15 word8 S + A - P
/// R_X86_64_DTPMOD64 16 word64
/// R_X86_64_DTPOFF64 17 word64
/// R_X86_64_TPOFF64 18 word64
/// R_X86_64_TLSGD 19 word32
/// R_X86_64_TLSLD 20 word32
/// R_X86_64_DTPOFF32 21 word32
/// R_X86_64_GOTTPOFF 22 word32
/// R_X86_64_TPOFF32 23 word32
/// R_X86_64_PC64 24 word64 S + A - P
/// R_X86_64_GOTOFF64 25 word64 S + A - GOT
/// R_X86_64_GOTPC32 26 word32 GOT + A - P
/// R_X86_64_SIZE32 32 word32 Z + A
/// R_X86_64_SIZE64 33 word64 Z + A
/// R_X86_64_GOTPC32_TLSDESC 34 word32
/// R_X86_64_TLSDESC_CALL 35 none
/// R_X86_64_TLSDESC 36 word64×2
/// R_X86_64_IRELATIVE 37 word64 indirect (B + A)
///
/// TLS information is at http://people.redhat.com/aoliva/writeups/TLS/RFC-TLSDESC-x86.txt
/// R_X86_64_IRELATIVE is similar to R_X86_64_RELATIVE except that
/// the value used in this relocation is the program address returned by the function,
/// which takes no arguments, at the address of the result of the corresponding
/// R_X86_64_RELATIVE relocation.

pub use super::super::elf::rela::*;

#[repr(C)]
#[derive(Clone, PartialEq, Default)]
pub struct Rela {
    pub r_offset: u64, // Address
    pub r_info: u64, // Relocation type and symbol index
    pub r_addend: i64, // Addend
}

pub const SIZEOF_RELA: usize = 8 + 8 + 8;

#[inline(always)]
pub fn r_sym(info: u64) -> u64 {
    info >> 32
}

#[inline(always)]
pub fn r_type(info: u64) -> u64 {
    info & 0xffffffff
}

#[inline(always)]
pub fn r_info(sym: u64, typ: u64) -> u64 {
    (sym << 32) + typ
}

elf_rela_impure_impl!(
    pub fn from_fd(fd: &mut File, offset: usize, size: usize, is_lsb: bool) -> io::Result<Vec<Rela>> {
        use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
        let count = size / SIZEOF_RELA;
        let mut res = Vec::with_capacity(count);

        try!(fd.seek(Start(offset as u64)));
        for _ in 0..count {
            let mut rela = Rela::default();

            if is_lsb {
                rela.r_offset = try!(fd.read_u64::<LittleEndian>());
                rela.r_info = try!(fd.read_u64::<LittleEndian>());
                rela.r_addend = try!(fd.read_i64::<LittleEndian>());
            } else {
                rela.r_offset = try!(fd.read_u64::<BigEndian>());
                rela.r_info = try!(fd.read_u64::<BigEndian>());
                rela.r_addend = try!(fd.read_i64::<BigEndian>());
            }

            res.push(rela);
        }

        res.dedup();
        Ok(res)
    });
