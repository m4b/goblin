use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom::Start;
use std::io;
use std::fmt;
use std::slice;
use super::program_header::{ProgramHeader, PT_DYNAMIC};
use super::strtab::Strtab;

pub use super::super::dyn::*;

/// An entry in the dynamic array
#[repr(C)]
#[derive(Clone, PartialEq, Default)]
pub struct Dyn {
    pub d_tag: u64, // Dynamic entry type
    pub d_val: u64, // Integer value
}

pub const SIZEOF_DYN: usize = 16;

impl fmt::Debug for Dyn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "d_tag: {} d_val: 0x{:x}",
               tag_to_str(self.d_tag),
               self.d_val)
    }
}

#[cfg(not(feature = "no_endian_fd"))]
/// Returns a vector of dynamic entries from the given fd and program headers
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
}

#[cfg(feature = "no_endian_fd")]
/// Returns a vector of dynamic entries from the given fd and program headers
pub fn from_fd(mut fd: &File, phdrs: &[ProgramHeader], _: bool) -> io::Result<Option<Vec<Dyn>>> {
    use std::io::Read;
    for phdr in phdrs {
        if phdr.p_type == PT_DYNAMIC {
            let filesz = phdr.p_filesz as usize;
            let dync = filesz / SIZEOF_DYN;
            let mut bytes = vec![0u8; filesz];
            try!(fd.seek(Start(phdr.p_offset)));
            try!(fd.read(&mut bytes));
            let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut Dyn, dync) };
            let mut dyns = Vec::with_capacity(dync);
            dyns.extend_from_slice(bytes);
            dyns.dedup();
            return Ok(Some(dyns));
        }
    }
    Ok(None)
}

/// Given a bias and a memory address (typically for a _correctly_ mmap'd binary in memory), returns the `_DYNAMIC` array as a slice of that memory
pub unsafe fn from_raw<'a>(bias: u64, vaddr: u64) -> &'a [Dyn] {
    let dynp = vaddr.wrapping_add(bias) as *const Dyn;
    let mut idx = 0;
    while (*dynp.offset(idx)).d_tag != DT_NULL {
        idx += 1;
    }
    slice::from_raw_parts(dynp, idx as usize)
}

// TODO: these bare functions have always seemed awkward, but not sure where they should go...

/// Maybe gets and returns the dynamic array with the same lifetime as the [phdrs], using the provided bias with wrapping addition.
/// If the bias is wrong, it will either segfault or give you incorrect values, beware
pub unsafe fn from_phdrs<'a>(bias: u64, phdrs: &'a [ProgramHeader]) -> Option<&'a [Dyn]> {
    for phdr in phdrs {
        if phdr.p_type == PT_DYNAMIC {
            return Some(from_raw(bias, phdr.p_vaddr));
        }
    }
    None
}

/// Gets the needed libraries from the `_DYNAMIC` array, with the str slices lifetime tied to the dynamic array/strtab's lifetime(s)
pub fn get_needed<'a, 'b>(dyns: &'a [Dyn], strtab: &'b Strtab<'a>, count: usize) -> Vec<&'a str> {
    let mut needed = Vec::with_capacity(count);
    for dyn in dyns {
        if dyn.d_tag == DT_NEEDED {
            let lib = strtab.get(dyn.d_val as usize);
            needed.push(lib);
        }
    }
    needed
}

// TODO: make this portable in 32 bit world somehow?
/// Important dynamic linking info generated via a single pass through the _DYNAMIC array
pub struct DynamicInfo {
    pub rela: usize,
    pub relasz: usize,
    pub relaent: u64,
    pub relacount: usize,
    pub gnu_hash: Option<u64>,
    pub hash: Option<u64>,
    pub strtab: usize,
    pub strsz: usize,
    pub symtab: usize,
    pub syment: usize,
    pub pltgot: Option<u64>,
    pub pltrelsz: usize,
    pub pltrel: u64,
    pub jmprel: usize,
    pub verneed: u64,
    pub verneednum: u64,
    pub versym: u64,
    pub init: u64,
    pub fini: u64,
    pub init_array: u64,
    pub init_arraysz: usize,
    pub fini_array: u64,
    pub fini_arraysz: usize,
    pub needed_count: usize,
    pub flags: u64,
    pub flags_1: u64,
    pub soname: usize,
}

impl DynamicInfo {
    pub fn new(dynamic: &[Dyn], bias: usize) -> DynamicInfo {
        let bias = bias as u64;
        let mut rela = 0;
        let mut relasz = 0;
        let mut relaent = 0;
        let mut relacount = 0;
        let mut gnu_hash = None;
        let mut hash = None;
        let mut strtab = 0;
        let mut strsz = 0;
        let mut symtab = 0;
        let mut syment = 0;
        let mut pltgot = None;
        let mut pltrelsz = 0;
        let mut pltrel = 0;
        let mut jmprel = 0;
        let mut verneed = 0;
        let mut verneednum = 0;
        let mut versym = 0;
        let mut init = 0;
        let mut fini = 0;
        let mut init_array = 0;
        let mut init_arraysz = 0;
        let mut fini_array = 0;
        let mut fini_arraysz = 0;
        let mut needed_count = 0;
        let mut flags = 0;
        let mut flags_1 = 0;
        let mut soname = 0;
        for dyn in dynamic {
            match dyn.d_tag {
                DT_RELA => rela = dyn.d_val.wrapping_add(bias) as usize, // .rela.dyn
                DT_RELASZ => relasz = dyn.d_val as usize,
                DT_RELAENT => relaent = dyn.d_val,
                DT_RELACOUNT => relacount = dyn.d_val as usize,
                DT_GNU_HASH => gnu_hash = Some(dyn.d_val.wrapping_add(bias)),
                DT_HASH => hash = Some(dyn.d_val.wrapping_add(bias)),
                DT_STRTAB => strtab = dyn.d_val.wrapping_add(bias) as usize,
                DT_STRSZ => strsz = dyn.d_val as usize,
                DT_SYMTAB => symtab = dyn.d_val.wrapping_add(bias) as usize,
                DT_SYMENT => syment = dyn.d_val as usize,
                DT_PLTGOT => pltgot = Some(dyn.d_val.wrapping_add(bias)),
                DT_PLTRELSZ => pltrelsz = dyn.d_val as usize,
                DT_PLTREL => pltrel = dyn.d_val,
                DT_JMPREL => jmprel = dyn.d_val.wrapping_add(bias) as usize, // .rela.plt
                DT_VERNEED => verneed = dyn.d_val.wrapping_add(bias),
                DT_VERNEEDNUM => verneednum = dyn.d_val,
                DT_VERSYM => versym = dyn.d_val.wrapping_add(bias),
                DT_INIT => init = dyn.d_val.wrapping_add(bias),
                DT_FINI => fini = dyn.d_val.wrapping_add(bias),
                DT_INIT_ARRAY => init_array = dyn.d_val.wrapping_add(bias),
                DT_INIT_ARRAYSZ => init_arraysz = dyn.d_val,
                DT_FINI_ARRAY => fini_array = dyn.d_val.wrapping_add(bias),
                DT_FINI_ARRAYSZ => fini_arraysz = dyn.d_val,
                DT_NEEDED => needed_count += 1,
                DT_FLAGS => flags = dyn.d_val,
                DT_FLAGS_1 => flags_1 = dyn.d_val,
                DT_SONAME => soname = dyn.d_val,
                _ => (),
            }
        }

        DynamicInfo {
            rela: rela,
            relasz: relasz,
            relaent: relaent,
            relacount: relacount,
            gnu_hash: gnu_hash,
            hash: hash,
            strtab: strtab,
            strsz: strsz,
            symtab: symtab,
            syment: syment,
            pltgot: pltgot,
            pltrelsz: pltrelsz,
            pltrel: pltrel,
            jmprel: jmprel,
            verneed: verneed,
            verneednum: verneednum,
            versym: versym,
            init: init,
            fini: fini,
            init_array: init_array,
            init_arraysz: init_arraysz as usize,
            fini_array: fini_array,
            fini_arraysz: fini_arraysz as usize,
            needed_count: needed_count,
            flags: flags,
            flags_1: flags_1,
            soname: soname as usize,
        }
    }
}

impl fmt::Debug for DynamicInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let gnu_hash = if let Some(addr) = self.gnu_hash { addr } else { 0 };
        let hash = if let Some(addr) = self.hash { addr } else { 0 };
        let pltgot = if let Some(addr) = self.pltgot { addr } else { 0 };
        write!(f, "rela: 0x{:x} relasz: {} relaent: {} relacount: {} gnu_hash: 0x{:x} hash: 0x{:x} strtab: 0x{:x} strsz: {} symtab: 0x{:x} syment: {} pltgot: 0x{:x} pltrelsz: {} pltrel: {} jmprel: 0x{:x} verneed: 0x{:x} verneednum: {} versym: 0x{:x} init: 0x{:x} fini: 0x{:x} needed_count: {}",
               self.rela,
               self.relasz,
               self.relaent,
               self.relacount,
               gnu_hash,
               hash,
               self.strtab,
               self.strsz,
               self.symtab,
               self.syment,
               pltgot,
               self.pltrelsz,
               self.pltrel,
               self.jmprel,
               self.verneed,
               self.verneednum,
               self.versym,
               self.init,
               self.fini,
               self.needed_count,
               )
    }
}
