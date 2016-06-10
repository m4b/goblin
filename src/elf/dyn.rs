use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom::Start;
use std::io;
use std::fmt;
use std::slice;
use elf::program_header::{ProgramHeader, PT_DYNAMIC};
use elf::strtab::Strtab;

// I decided to use u64 instead of u32 due to pattern matching use case
// seems safer to cast the elf32's d_tag from u32 -> u64 at runtime
// instead of casting the elf64's d_tag from u64 -> u32 at runtime
pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_PLTRELSZ: u64 = 2;
pub const DT_PLTGOT: u64 = 3;
pub const DT_HASH: u64 = 4;
pub const DT_STRTAB: u64 = 5;
pub const DT_SYMTAB: u64 = 6;
pub const DT_RELA: u64 = 7;
pub const DT_RELASZ: u64 = 8;
pub const DT_RELAENT: u64 = 9;
pub const DT_STRSZ: u64 = 10;
pub const DT_SYMENT: u64 = 11;
pub const DT_INIT: u64 = 12;
pub const DT_FINI: u64 = 13;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_SYMBOLIC: u64 = 16;
pub const DT_REL: u64 = 17;
pub const DT_RELSZ: u64 = 18;
pub const DT_RELENT: u64 = 19;
pub const DT_PLTREL: u64 = 20;
pub const DT_DEBUG: u64 = 21;
pub const DT_TEXTREL: u64 = 22;
pub const DT_JMPREL: u64 = 23;
pub const DT_BIND_NOW: u64 = 24;
pub const DT_INIT_ARRAY: u64 = 25;
pub const DT_FINI_ARRAY: u64 = 26;
pub const DT_INIT_ARRAYSZ: u64 = 27;
pub const DT_FINI_ARRAYSZ: u64 = 28;
pub const DT_RUNPATH: u64 = 29;
pub const DT_FLAGS: u64 = 30;
pub const DT_ENCODING: u64 = 32;
pub const DT_PREINIT_ARRAY: u64 = 32;
pub const DT_PREINIT_ARRAYSZ: u64 = 33;
pub const DT_NUM: u64 = 34;
pub const DT_LOOS: u64 = 0x6000000d;
pub const DT_HIOS: u64 = 0x6ffff000;
pub const DT_LOPROC: u64 = 0x70000000;
pub const DT_HIPROC: u64 = 0x7fffffff;
// pub const DT_PROCNUM: u64 = DT_MIPS_NUM;
pub const DT_VERSYM: u64 = 0x6ffffff0;
pub const DT_RELACOUNT: u64 = 0x6ffffff9;
pub const DT_RELCOUNT: u64 = 0x6ffffffa;
pub const DT_GNU_HASH: u64 = 0x6ffffef5;
pub const DT_VERDEF: u64 = 0x6ffffffc;
pub const DT_VERDEFNUM: u64 = 0x6ffffffd;
pub const DT_VERNEED: u64 = 0x6ffffffe;
pub const DT_VERNEEDNUM: u64 = 0x6fffffff;
pub const DT_FLAGS_1: u64 = 0x6ffffffb;

/// An entry in the dynamic array
#[repr(C)]
#[derive(Clone, PartialEq, Default)]
pub struct Dyn {
    pub d_tag: u64, // Dynamic entry type
    pub d_val: u64, // Integer value
}

pub const SIZEOF_DYN: usize = 16;

/// Converts a tag to its string representation
#[inline]
fn tag_to_str(tag: u64) -> &'static str {
    match tag {
        DT_NULL => "DT_NULL",
        DT_NEEDED => "DT_NEEDED",
        DT_PLTRELSZ => "DT_PLTRELSZ",
        DT_PLTGOT => "DT_PLTGOT",
        DT_HASH => "DT_HASH",
        DT_STRTAB => "DT_STRTAB",
        DT_SYMTAB => "DT_SYMTAB",
        DT_RELA => "DT_RELA",
        DT_RELASZ => "DT_RELASZ",
        DT_RELAENT => "DT_RELAENT",
        DT_STRSZ => "DT_STRSZ",
        DT_SYMENT => "DT_SYMENT",
        DT_INIT => "DT_INIT",
        DT_FINI => "DT_FINI",
        DT_SONAME => "DT_SONAME",
        DT_RPATH => "DT_RPATH",
        DT_SYMBOLIC => "DT_SYMBOLIC",
        DT_REL => "DT_REL",
        DT_RELSZ => "DT_RELSZ",
        DT_RELENT => "DT_RELENT",
        DT_PLTREL => "DT_PLTREL",
        DT_DEBUG => "DT_DEBUG",
        DT_TEXTREL => "DT_TEXTREL",
        DT_JMPREL => "DT_JMPREL",
        DT_BIND_NOW => "DT_BIND_NOW",
        DT_INIT_ARRAY => "DT_INIT_ARRAY",
        DT_FINI_ARRAY => "DT_FINI_ARRAY",
        DT_INIT_ARRAYSZ => "DT_INIT_ARRAYSZ",
        DT_FINI_ARRAYSZ => "DT_FINI_ARRAYSZ",
        DT_RUNPATH => "DT_RUNPATH",
        DT_FLAGS => "DT_FLAGS",
        DT_PREINIT_ARRAY => "DT_PREINIT_ARRAY",
        DT_PREINIT_ARRAYSZ => "DT_PREINIT_ARRAYSZ",
        DT_NUM => "DT_NUM",
        DT_LOOS => "DT_LOOS",
        DT_HIOS => "DT_HIOS",
        DT_LOPROC => "DT_LOPROC",
        DT_HIPROC => "DT_HIPROC",
        DT_VERSYM => "DT_VERSYM",
        DT_RELACOUNT => "DT_RELACOUNT",
        DT_RELCOUNT => "DT_RELCOUNT",
        DT_GNU_HASH => "DT_GNU_HASH",
        DT_VERDEF => "DT_VERDEF",
        DT_VERDEFNUM => "DT_VERDEFNUM",
        DT_VERNEED => "DT_VERNEED",
        DT_VERNEEDNUM => "DT_VERNEEDNUM",
        DT_FLAGS_1 => "DT_FLAGS_1",
        _ => "UNKNOWN_TAG",
    }
}

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

// Values of `d_un.d_val` in the DT_FLAGS entry
pub const DF_ORIGIN: u64 = 0x00000001; // Object may use DF_ORIGIN
pub const DF_SYMBOLIC: u64 = 0x00000002; // Symbol resolutions starts here
pub const DF_TEXTREL: u64 = 0x00000004; // Object contains text relocations
pub const DF_BIND_NOW: u64 = 0x00000008; // No lazy binding for this object
pub const DF_STATIC_TLS: u64 = 0x00000010; // Module uses the static TLS model

// State flags selectable in the `d_un.d_val` element of the DT_FLAGS_1 entry in the dynamic section.
pub const DF_1_NOW: u64 = 0x00000001; // Set RTLD_NOW for this object
pub const DF_1_GLOBAL: u64 = 0x00000002; // Set RTLD_GLOBAL for this object
pub const DF_1_GROUP: u64 = 0x00000004; // Set RTLD_GROUP for this object
pub const DF_1_NODELETE: u64 = 0x00000008; // Set RTLD_NODELETE for this object
pub const DF_1_LOADFLTR: u64 = 0x00000010; // Trigger filtee loading at runtime
pub const DF_1_INITFIRST: u64 = 0x00000020; // Set RTLD_INITFIRST for this object
pub const DF_1_NOOPEN: u64 = 0x00000040; // Set RTLD_NOOPEN for this object
pub const DF_1_ORIGIN: u64 = 0x00000080; // $ORIGIN must be handled
pub const DF_1_DIRECT: u64 = 0x00000100; // Direct binding enabled
pub const DF_1_TRANS: u64 = 0x00000200;
pub const DF_1_INTERPOSE: u64 = 0x00000400; // Object is used to interpose
pub const DF_1_NODEFLIB: u64 = 0x00000800; // Ignore default lib search path
pub const DF_1_NODUMP: u64 = 0x00001000; // Object can't be dldump'ed
pub const DF_1_CONFALT: u64 = 0x00002000; // Configuration alternative created
pub const DF_1_ENDFILTEE: u64 = 0x00004000; // Filtee terminates filters search
pub const DF_1_DISPRELDNE: u64 = 0x00008000; // Disp reloc applied at build time
pub const DF_1_DISPRELPND: u64 = 0x00010000; // Disp reloc applied at run-time
pub const DF_1_NODIRECT: u64 = 0x00020000; // Object has no-direct binding
pub const DF_1_IGNMULDEF: u64 = 0x00040000;
pub const DF_1_NOKSYMS: u64 = 0x00080000;
pub const DF_1_NOHDR: u64 = 0x00100000;
pub const DF_1_EDITED: u64 = 0x00200000; // Object is modified after built
pub const DF_1_NORELOC: u64 = 0x00400000;
pub const DF_1_SYMINTPOSE: u64 = 0x00800000; // Object has individual interposers
pub const DF_1_GLOBAUDIT: u64 = 0x01000000; // Global auditing required
pub const DF_1_SINGLETON: u64 = 0x02000000; // Singleton symbols are used
