#[cfg(not(feature = "no_elf"))]
pub mod _64;
#[cfg(not(feature = "no_elf32"))]
pub mod _32;

// These are shareable values for the 32/64 bit implementations
// They are publicly re-exported by the pub-using module
mod header {
    pub const ET_NONE: u16 = 0; // No file type
    pub const ET_REL: u16 = 1; // Relocatable file
    pub const ET_EXEC: u16 = 2; // Executable file
    pub const ET_DYN: u16 = 3; // Shared object file
    pub const ET_CORE: u16 = 4; // Core file
    pub const ET_NUM: u16 = 5; // Number of defined types

    pub const EI_CLASS: u8 = 4; // File class byte index
    pub const ELFCLASSNONE: u8 = 0; // Invalid class
    pub const ELFCLASS32: u8 = 1; //32-bit objects
    pub const ELFCLASS64: u8 = 2; // 64-bit objects
    pub const ELFCLASSNUM: u8 = 3;

    pub const EI_DATA: usize = 5; // Data encoding byte index
    pub const ELFDATANONE: u8 = 0; // Invalid data encoding
    pub const ELFDATA2LSB: u8 = 1; // 2's complement, little endian
    pub const ELFDATA2MSB: u8 = 2; // 2's complement, big endian
}

mod sym {
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

mod program_header {
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
