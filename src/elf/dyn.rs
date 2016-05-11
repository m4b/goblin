/// TODO: need to add the DF_1* and DF_* flags here...

use std::fs::File;
use std::io::Read;
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
#[derive(Clone, PartialEq)]
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

pub fn from_fd(mut fd: &File, phdrs: &[ProgramHeader]) -> io::Result<Option<Vec<Dyn>>> {
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

/// Maybe gets and returns the dynamic array with the same lifetime as the [phdrs], using the provided bias with wrapping addition.
/// If the bias is wrong, it will either segfault or give you incorrect values, beware
pub unsafe fn get_dynamic_array<'a>(bias: u64, phdrs: &'a [ProgramHeader]) -> Option<&'a [Dyn]> {
    for phdr in phdrs {
        if phdr.p_type == PT_DYNAMIC {
            let dynp = phdr.p_vaddr.wrapping_add(bias) as *const Dyn;
            let mut idx = 0;
            while (*dynp.offset(idx)).d_tag != DT_NULL {
                idx += 1;
            }
            return Some(slice::from_raw_parts(dynp, idx as usize));
        }
    }
    None
}

/// Gets the needed libraries from the `_DYNAMIC` array, with the str slices lifetime tied to the dynamic arrays lifetime
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

/// Important dynamic LinkInfo generated via a single pass through the _DYNAMIC array
pub struct LinkInfo {
    pub rela: usize,
    pub relasz: u64, // TODO: make this a usize?
    pub relaent: u64,
    pub relacount: usize,
    pub gnu_hash: u64,
    pub hash: u64,
    pub strtab: usize,
    pub strsz: usize,
    pub symtab: usize,
    pub syment: usize,
    pub pltgot: u64,
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

impl LinkInfo {
    pub fn new(dynamic: &[Dyn], bias: usize) -> LinkInfo {
        let bias = bias as u64;
        let mut rela = 0;
        let mut relasz = 0;
        let mut relaent = 0;
        let mut relacount = 0;
        let mut gnu_hash = 0;
        let mut hash = 0;
        let mut strtab = 0;
        let mut strsz = 0;
        let mut symtab = 0;
        let mut syment = 0;
        let mut pltgot = 0;
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
                DT_RELASZ => relasz = dyn.d_val,
                DT_RELAENT => relaent = dyn.d_val,
                DT_RELACOUNT => relacount = dyn.d_val as usize,
                DT_GNU_HASH => gnu_hash = dyn.d_val.wrapping_add(bias),
                DT_HASH => hash = dyn.d_val.wrapping_add(bias),
                DT_STRTAB => strtab = dyn.d_val.wrapping_add(bias) as usize,
                DT_STRSZ => strsz = dyn.d_val as usize,
                DT_SYMTAB => symtab = dyn.d_val.wrapping_add(bias) as usize,
                DT_SYMENT => syment = dyn.d_val as usize,
                DT_PLTGOT => pltgot = dyn.d_val.wrapping_add(bias),
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

        LinkInfo {
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

impl fmt::Debug for LinkInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "rela: 0x{:x} relasz: {} relaent: {} relacount: {} gnu_hash: 0x{:x} hash: 0x{:x} strtab: 0x{:x} strsz: {} symtab: 0x{:x} syment: {} pltgot: 0x{:x} pltrelsz: {} pltrel: {} jmprel: 0x{:x} verneed: 0x{:x} verneednum: {} versym: 0x{:x} init: 0x{:x} fini: 0x{:x} needed_count: {}",
               self.rela,
               self.relasz,
               self.relaent,
               self.relacount,
               self.gnu_hash,
               self.hash,
               self.strtab,
               self.strsz,
               self.symtab,
               self.syment,
               self.pltgot,
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

// TODO add these
// Values of `d_un.d_val' in the DT_FLAGS entry.  */
// #define DF_ORIGIN	0x00000001	/* Object may use DF_ORIGIN */
// #define DF_SYMBOLIC	0x00000002	/* Symbol resolutions starts here */
// #define DF_TEXTREL	0x00000004	/* Object contains text relocations */
// #define DF_BIND_NOW	0x00000008	/* No lazy binding for this object */
// #define DF_STATIC_TLS	0x00000010	/* Module uses the static TLS model */
//
// State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1
// entry in the dynamic section.  */
// #define DF_1_NOW	0x00000001	/* Set RTLD_NOW for this object.  */
// #define DF_1_GLOBAL	0x00000002	/* Set RTLD_GLOBAL for this object.  */
// #define DF_1_GROUP	0x00000004	/* Set RTLD_GROUP for this object.  */
// #define DF_1_NODELETE	0x00000008	/* Set RTLD_NODELETE for this object.*/
// #define DF_1_LOADFLTR	0x00000010	/* Trigger filtee loading at runtime.*/
// #define DF_1_INITFIRST	0x00000020	/* Set RTLD_INITFIRST for this object*/
// #define DF_1_NOOPEN	0x00000040	/* Set RTLD_NOOPEN for this object.  */
// #define DF_1_ORIGIN	0x00000080	/* $ORIGIN must be handled.  */
// #define DF_1_DIRECT	0x00000100	/* Direct binding enabled.  */
// #define DF_1_TRANS	0x00000200
// #define DF_1_INTERPOSE	0x00000400	/* Object is used to interpose.  */
// #define DF_1_NODEFLIB	0x00000800	/* Ignore default lib search path.  */
// #define DF_1_NODUMP	0x00001000	/* Object can't be dldump'ed.  */
// #define DF_1_CONFALT	0x00002000	/* Configuration alternative created.*/
// #define DF_1_ENDFILTEE	0x00004000	/* Filtee terminates filters search. */
// #define	DF_1_DISPRELDNE	0x00008000	/* Disp reloc applied at build time. */
// #define	DF_1_DISPRELPND	0x00010000	/* Disp reloc applied at run-time.  */
// #define	DF_1_NODIRECT	0x00020000	/* Object has no-direct binding. */
// #define	DF_1_IGNMULDEF	0x00040000
// #define	DF_1_NOKSYMS	0x00080000
// #define	DF_1_NOHDR	0x00100000
// #define	DF_1_EDITED	0x00200000	/* Object is modified after built.  */
// #define	DF_1_NORELOC	0x00400000
// #define	DF_1_SYMINTPOSE	0x00800000	/* Object has individual interposers.  */
// #define	DF_1_GLOBAUDIT	0x01000000	/* Global auditing required.  */
// #define	DF_1_SINGLETON	0x02000000	/* Singleton symbols are used.  */
//
//
