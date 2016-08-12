//! Access ELF constants, other helper functions, which are independent of ELF bithood.
//! Also provides simple parser which returns an Elf64 or Elf32 "pre-built" binary.
//! **WARNING**: to use the automagic ELF datatype union parser, you _must_ enable both elf and elf32 features - i.e., do not use `no_elf` **NOR** `no_elf32`, otherwise you'll get obscure errors about [goblin::elf::from_fd](fn.from_fd.html) missing.

// #[doc(hidden)]
// #[cfg(not(feature = "no_elf"))]
// mod _64;

// #[doc(hidden)]
// #[cfg(not(feature = "no_elf32"))]
// mod _32;

// These are shareable values for the 32/64 bit implementations
// They are publicly re-exported by the pub-using module
pub mod header {
    pub const ET_NONE: u16 = 0; // No file type
    pub const ET_REL: u16 = 1; // Relocatable file
    pub const ET_EXEC: u16 = 2; // Executable file
    pub const ET_DYN: u16 = 3; // Shared object file
    pub const ET_CORE: u16 = 4; // Core file
    pub const ET_NUM: u16 = 5; // Number of defined types

    pub const EI_CLASS: usize = 4; // File class byte index
    pub const ELFCLASSNONE: u8 = 0; // Invalid class
    pub const ELFCLASS32: u8 = 1; //32-bit objects
    pub const ELFCLASS64: u8 = 2; // 64-bit objects
    pub const ELFCLASSNUM: u8 = 3;

    pub const EI_DATA: usize = 5; // Data encoding byte index
    pub const ELFDATANONE: u8 = 0; // Invalid data encoding
    pub const ELFDATA2LSB: u8 = 1; // 2's complement, little endian
    pub const ELFDATA2MSB: u8 = 2; // 2's complement, big endian

    pub const SIZEOF_IDENT: usize = 16;

    #[inline]
    pub fn et_to_str(et: u16) -> &'static str {
        match et {
            ET_NONE => "NONE",
            ET_REL => "REL",
            ET_EXEC => "EXEC",
            ET_DYN => "DYN",
            ET_CORE => "CORE",
            ET_NUM => "NUM",
            _ => "UNKNOWN_ET",
        }
    }

    #[cfg(not(feature = "pure"))]
    pub mod impure {
        use super::*;

        use std::fs::File;
        use std::io;
        use std::io::Read;
        use std::io::Seek;
        use std::io::SeekFrom::Start;

        pub fn peek(fd: &mut File) -> io::Result<(u8, bool)> {
            let mut header = [0u8; SIZEOF_IDENT];
            try!(fd.seek(Start(0)));
            match try!(fd.read(&mut header)) {
                SIZEOF_IDENT => {
                    let class = header[EI_CLASS];
                    let is_lsb = header[EI_DATA] == ELFDATA2LSB;
                    Ok((class, is_lsb))
                }
                count => { io_error!("Error: {:?} size is smaller than an ELF identication header", count) }
            }
        }
    }
}

pub mod sym {
    // sym bindings
    pub const STB_LOCAL: u8 = 0; // Local symbol
    pub const STB_GLOBAL: u8 = 1; // Global symbol
    pub const STB_WEAK: u8 = 2; // Weak symbol
    pub const STB_NUM: u8 = 3; // Number of defined types.
    pub const STB_LOOS: u8 = 10; // Start of OS-specific
    pub const STB_GNU_UNIQUE: u8 = 10; // Unique symbol.
    pub const STB_HIOS: u8 = 12; // End of OS-specific
    pub const STB_LOPROC: u8 = 13; // Start of processor-specific
    pub const STB_HIPROC: u8 = 15; // End of processor-specific
    // sym types
    pub const STT_NOTYPE: u8 = 0; // Symbol type is unspecified
    pub const STT_OBJECT: u8 = 1; // Symbol is a data object
    pub const STT_FUNC: u8 = 2; // Symbol is a code object
    pub const STT_SECTION: u8 = 3; // Symbol associated with a section
    pub const STT_FILE: u8 = 4; // Symbol's name is file name
    pub const STT_COMMON: u8 = 5; // Symbol is a common data object
    pub const STT_TLS: u8 = 6; // Symbol is thread-local data object
    pub const STT_NUM: u8 = 7; // Number of defined types
    pub const STT_LOOS: u8 = 10; // Start of OS-specific
    pub const STT_GNU_IFUNC: u8 = 10; // Symbol is indirect code object
    pub const STT_HIOS: u8 = 12; // End of OS-specific
    pub const STT_LOPROC: u8 = 13; // Start of processor-specific
    pub const STT_HIPROC: u8 = 15; // End of processor-specific

    #[inline(always)]
    pub fn st_bind(info: u8) -> u8 {
        info >> 4
    }

    #[inline(always)]
    pub fn st_type(info: u8) -> u8 {
        info & 0xf
    }

    #[inline(always)]
    pub fn is_import(info: u8, value: u8) -> bool {
        let binding = st_bind(info);
        binding == STB_GLOBAL && value == 0
    }

    /// Convenience function to get the &'static str type from the symbols st_info
    pub fn get_type(info: u8) -> &'static str {
        type_to_str(st_type(info))
    }

    #[inline]
    pub fn bind_to_str(typ: u8) -> &'static str {
        match typ {
            STB_LOCAL => "LOCAL",
            STB_GLOBAL => "GLOBAL",
            STB_WEAK => "WEAK",
            STB_NUM => "NUM",
            STB_GNU_UNIQUE => "GNU_UNIQUE",
            _ => "UNKNOWN_STB",
        }
    }

    #[inline]
    pub fn type_to_str(typ: u8) -> &'static str {
        match typ {
            STT_NOTYPE => "NOTYPE",
            STT_OBJECT => "OBJECT",
            STT_FUNC => "FUNC",
            STT_SECTION => "SECTION",
            STT_FILE => "FILE",
            STT_COMMON => "COMMON",
            STT_TLS => "TLS",
            STT_NUM => "NUM",
            STT_GNU_IFUNC => "GNU_IFUNC",
            _ => "UNKNOWN_STT",
        }
    }
}

pub mod program_header {
    pub const PT_NULL: u32 = 0;
    pub const PT_LOAD: u32 = 1;
    pub const PT_DYNAMIC: u32 = 2;
    pub const PT_INTERP: u32 = 3;
    pub const PT_NOTE: u32 = 4;
    pub const PT_SHLIB: u32 = 5;
    pub const PT_PHDR: u32 = 6;
    pub const PT_TLS: u32 = 7;
    pub const PT_NUM: u32 = 8;
    pub const PT_LOOS: u32 = 0x60000000;
    pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
    pub const PT_GNU_STACK: u32 = 0x6474e551;
    pub const PT_GNU_RELRO: u32 = 0x6474e552;
    pub const PT_LOSUNW: u32 = 0x6ffffffa;
    pub const PT_SUNWBSS: u32 = 0x6ffffffa;
    pub const PT_SUNWSTACK: u32 = 0x6ffffffb;
    pub const PT_HISUNW: u32 = 0x6fffffff;
    pub const PT_HIOS: u32 = 0x6fffffff;
    pub const PT_LOPROC: u32 = 0x70000000;
    pub const PT_HIPROC: u32 = 0x7fffffff;

    /// Segment is executable
    pub const PF_X: u32 = 1 << 0;

    /// Segment is writable
    pub const PF_W: u32 = 1 << 1;

    /// Segment is readable
    pub const PF_R: u32 = 1 << 2;

    pub fn pt_to_str(pt: u32) -> &'static str {
        match pt {
            PT_NULL => "PT_NULL",
            PT_LOAD => "PT_LOAD",
            PT_DYNAMIC => "PT_DYNAMIC",
            PT_INTERP => "PT_INTERP",
            PT_NOTE => "PT_NOTE",
            PT_SHLIB => "PT_SHLIB",
            PT_PHDR => "PT_PHDR",
            PT_TLS => "PT_TLS",
            PT_NUM => "PT_NUM",
            PT_LOOS => "PT_LOOS",
            PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
            PT_GNU_STACK => "PT_GNU_STACK",
            PT_GNU_RELRO => "PT_GNU_RELRO",
            PT_SUNWBSS => "PT_SUNWBSS",
            PT_SUNWSTACK => "PT_SUNWSTACK",
            PT_HIOS => "PT_HIOS",
            PT_LOPROC => "PT_LOPROC",
            PT_HIPROC => "PT_HIPROC",
            _ => "UNKNOWN_PT",
        }
    }
}

pub mod dyn {
    // TODO: figure out what's the best, most friendly + safe API choice here - u32s or u64s
    // remember that DT_TAG is "pointer sized"/used as address sometimes
    // Original rationale: I decided to use u64 instead of u32 due to pattern matching use case
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

    /// Converts a tag to its string representation
    #[inline]
    pub fn tag_to_str(tag: u64) -> &'static str {
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

}

pub mod rela {
    pub const R_X86_64_NONE: u64 = 0; // No reloc
    pub const R_X86_64_64: u64 = 1; // Direct 64 bit
    pub const R_X86_64_PC32: u64 = 2; // PC relative 32 bit signed
    pub const R_X86_64_GOT32: u64 = 3; // 32 bit GOT entry
    pub const R_X86_64_PLT32: u64 = 4; // 32 bit PLT address
    pub const R_X86_64_COPY: u64 = 5; // Copy symbol at runtime
    pub const R_X86_64_GLOB_DAT: u64 = 6; // Create GOT entry
    pub const R_X86_64_JUMP_SLOT: u64 = 7; // Create PLT entry
    pub const R_X86_64_RELATIVE: u64 = 8; // Adjust by program base
    pub const R_X86_64_GOTPCREL: u64 = 9; // 32 bit signed PC relative offset to GOT
    pub const R_X86_64_32: u64 = 10; // Direct 32 bit zero extended
    pub const R_X86_64_32S: u64 = 11; // Direct 32 bit sign extended
    pub const R_X86_64_16: u64 = 12; // Direct 16 bit zero extended
    pub const R_X86_64_PC16: u64 = 13; // 16 bit sign extended pc relative
    pub const R_X86_64_8: u64 = 14; // Direct 8 bit sign extended
    pub const R_X86_64_PC8: u64 = 15; // 8 bit sign extended pc relative
    pub const R_X86_64_DTPMOD64: u64 = 16; // ID of module containing symbol
    pub const R_X86_64_DTPOFF64: u64 = 17; // Offset in module's TLS block
    pub const R_X86_64_TPOFF64: u64 = 18; // Offset in initial TLS block
    pub const R_X86_64_TLSGD: u64 = 19; // 32 bit signed PC relative offset to two GOT entries for GD symbol
    pub const R_X86_64_TLSLD: u64 = 20; // 32 bit signed PC relative offset to two GOT entries for LD symbol
    pub const R_X86_64_DTPOFF32: u64 = 21; // Offset in TLS block
    pub const R_X86_64_GOTTPOFF: u64 = 22; // 32 bit signed PC relative offset to GOT entry for IE symbol
    pub const R_X86_64_TPOFF32: u64 = 23; // Offset in initial TLS block
    pub const R_X86_64_PC64: u64 = 24; // PC relative 64 bit
    pub const R_X86_64_GOTOFF64: u64 = 25; // 64 bit offset to GOT
    pub const R_X86_64_GOTPC32: u64 = 26; // 32 bit signed pc relative offset to GOT
    pub const R_X86_64_GOT64: u64 = 27; // 64-bit GOT entry offset
    pub const R_X86_64_GOTPCREL64: u64 = 28; // 64-bit PC relative offset to GOT entry
    pub const R_X86_64_GOTPC64: u64 = 29; // 64-bit PC relative offset to GOT
    pub const R_X86_64_GOTPLT64: u64 = 30; // like GOT64, says PLT entry needed
    pub const R_X86_64_PLTOFF64: u64 = 31; // 64-bit GOT relative offset to PLT entry
    pub const R_X86_64_SIZE32: u64 = 32; // Size of symbol plus 32-bit addend
    pub const R_X86_64_SIZE64: u64 = 33; // Size of symbol plus 64-bit addend
    pub const R_X86_64_GOTPC32_TLSDESC: u64 = 34; // GOT offset for TLS descriptor.
    pub const R_X86_64_TLSDESC_CALL: u64 = 35; // Marker for call through TLS descriptor.
    pub const R_X86_64_TLSDESC: u64 = 36; // TLS descriptor.
    pub const R_X86_64_IRELATIVE: u64 = 37; // Adjust indirectly by program base
    pub const R_X86_64_RELATIVE64: u64 = 38; // 64-bit adjust by program base
    pub const R_X86_64_NUM: u64 = 39;

    #[inline]
    pub fn type_to_str(typ: u64) -> &'static str {
        match typ {
            R_X86_64_NONE => "NONE",
            R_X86_64_64 => "64",
            R_X86_64_PC32 => "PC32",
            R_X86_64_GOT32 => "GOT32",
            R_X86_64_PLT32 => "PLT32",
            R_X86_64_COPY => "COPY",
            R_X86_64_GLOB_DAT => "GLOB_DAT",
            R_X86_64_JUMP_SLOT => "JUMP_SLOT",
            R_X86_64_RELATIVE => "RELATIVE",
            R_X86_64_GOTPCREL => "GOTPCREL",
            R_X86_64_32 => "32",
            R_X86_64_32S => "32S",
            R_X86_64_16 => "16",
            R_X86_64_PC16 => "PC16",
            R_X86_64_8 => "8",
            R_X86_64_PC8 => "PC8",
            R_X86_64_DTPMOD64 => "DTPMOD64",
            R_X86_64_DTPOFF64 => "DTPOFF64",
            R_X86_64_TPOFF64 => "TPOFF64",
            R_X86_64_TLSGD => "TLSGD",
            R_X86_64_TLSLD => "TLSLD",
            R_X86_64_DTPOFF32 => "DTPOFF32",
            R_X86_64_GOTTPOFF => "GOTTPOFF",
            R_X86_64_TPOFF32 => "TPOFF32",
            R_X86_64_PC64 => "PC64",
            R_X86_64_GOTOFF64 => "GOTOFF64",
            R_X86_64_GOTPC32 => "GOTPC32",
            R_X86_64_GOT64 => "GOT64",
            R_X86_64_GOTPCREL64 => "GOTPCREL64",
            R_X86_64_GOTPC64 => "GOTPC64",
            R_X86_64_GOTPLT64 => "GOTPLT64",
            R_X86_64_PLTOFF64 => "PLTOFF64",
            R_X86_64_SIZE32 => "SIZE32",
            R_X86_64_SIZE64 => "SIZE64",
            R_X86_64_GOTPC32_TLSDESC => "GOTPC32_TLSDESC",
            R_X86_64_TLSDESC_CALL => "TLSDESC_CALL",
            R_X86_64_TLSDESC => "TLSDESC",
            R_X86_64_IRELATIVE => "IRELATIVE",
            R_X86_64_RELATIVE64 => "RELATIVE64",
            _ => "UNKNOWN_RELA_TYPE",
        }
    }
}

#[cfg(all(not(feature = "pure"), not(feature = "no_elf32"), not(feature = "no_elf")))]
pub use self::impure::*;

#[cfg(all(not(feature = "pure"), not(feature = "no_elf32"), not(feature = "no_elf")))]
mod impure {

    use std::fs::File;
    use std::io;
    //use std::io::Read;
    //use std::io::SeekFrom::Start;

    use super::header;
    use super::header::impure::*;

    use super::super::elf32;
    use super::super::elf64;

    #[derive(Debug)]
    pub enum Binary {
        Elf32(elf32::Binary),
        Elf64(elf64::Binary),
    }

    pub fn from_fd (fd: &mut File) -> io::Result<Binary> {
        match try!(peek(fd)) {
            (header::ELFCLASS64, _is_lsb) => {
                Ok(Binary::Elf64(try!(elf64::Binary::from_fd(fd))))
            },
            (header::ELFCLASS32, _is_lsb) => {
                unimplemented!()
            },
            (class, is_lsb) => {
                io_error!("Unknown values in ELF ident header: class: {} is_lsb: {}", class, is_lsb)
            }
        }
    }
}
