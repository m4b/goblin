#[cfg(feature = "std")]
pub trait ElfSectionHeader {
    /// Section name (string tbl index)
    fn sh_name(&self) -> usize;
    /// Section type
    fn sh_type(&self) -> u32;
    /// Section flags
    fn sh_flags(&self) -> u64;
    /// Section virtual addr at execution
    fn sh_addr(&self) -> u64;
    /// Section file offset
    fn sh_offset(&self) -> u64;
    /// Section size in bytes
    fn sh_size(&self) -> u64;
    /// Link to another section
    fn sh_link(&self) -> u32;
    /// Additional section information
    fn sh_info(&self) -> u32;
    /// Section alignment
    fn sh_addralign(&self) -> u64;
    /// Entry size if section holds table
    fn sh_entsize(&self) -> u64;
}

macro_rules! elf_section_header {
        ($size:ident) => {
            #[repr(C)]
            #[derive(Copy, Clone, Eq, PartialEq, Default)]
            pub struct SectionHeader {
                /// Section name (string tbl index)
                pub sh_name: u32,
                /// Section type
                pub sh_type: u32,
                /// Section flags
                pub sh_flags: $size,
                /// Section virtual addr at execution
                pub sh_addr: $size,
                /// Section file offset
                pub sh_offset: $size,
                /// Section size in bytes
                pub sh_size: $size,
                /// Link to another section
                pub sh_link: u32,
                /// Additional section information
                pub sh_info: u32,
                /// Section alignment
                pub sh_addralign: $size,
                /// Entry size if section holds table
                pub sh_entsize: $size,
            }
        }
    }

/// Undefined section.
pub const SHN_UNDEF: u32 = 0;
/// Start of reserved indices.
pub const SHN_LORESERVE: u32 = 0xff00;
/// Start of processor-specific.
pub const SHN_LOPROC: u32 = 0xff00;
/// Order section before all others (Solaris).
pub const SHN_BEFORE: u32 = 0xff00;
/// Order section after all others (Solaris).
pub const SHN_AFTER: u32 = 0xff01;
/// End of processor-specific.
pub const SHN_HIPROC: u32 = 0xff1f;
/// Start of OS-specific.
pub const SHN_LOOS: u32 = 0xff20;
/// End of OS-specific.
pub const SHN_HIOS: u32 = 0xff3f;
/// Associated symbol is absolute.
pub const SHN_ABS: u32 = 0xfff1;
/// Associated symbol is common.
pub const SHN_COMMON: u32 = 0xfff2;
/// Index is in extra table.
pub const SHN_XINDEX: u32 = 0xffff;
/// End of reserved indices.
pub const SHN_HIRESERVE: u32 = 0xffff;

// === Legal values for sh_type (section type). ===
/// Section header table entry unused.
pub const SHT_NULL: u32 = 0;
/// Program data.
pub const SHT_PROGBITS: u32 = 1;
/// Symbol table.
pub const SHT_SYMTAB: u32 = 2;
/// String table.
pub const SHT_STRTAB: u32 = 3;
/// Relocation entries with addends.
pub const SHT_RELA: u32 = 4;
/// Symbol hash table.
pub const SHT_HASH: u32 = 5;
/// Dynamic linking information.
pub const SHT_DYNAMIC: u32 = 6;
/// Notes.
pub const SHT_NOTE: u32 = 7;
/// Program space with no data (bss).
pub const SHT_NOBITS: u32 = 8;
/// Relocation entries, no addends.
pub const SHT_REL: u32 = 9;
/// Reserved.
pub const SHT_SHLIB: u32 = 10;
/// Dynamic linker symbol table.
pub const SHT_DYNSYM: u32 = 11;
/// Array of constructors.
pub const SHT_INIT_ARRAY: u32 = 14;
/// Array of destructors.
pub const SHT_FINI_ARRAY: u32 = 15;
/// Array of pre-constructors.
pub const SHT_PREINIT_ARRAY: u32 = 16;
/// Section group.
pub const SHT_GROUP: u32 = 17;
/// Extended section indeces.
pub const SHT_SYMTAB_SHNDX: u32 = 18;
/// Number of defined types.
pub const SHT_NUM: u32 = 19;
/// Start OS-specific.
pub const SHT_LOOS: u32 = 0x60000000;
/// Object attributes.
pub const SHT_GNU_ATTRIBUTES: u32 = 0x6ffffff5;
/// GNU-style hash table.
pub const SHT_GNU_HASH: u32 = 0x6ffffff6;
/// Prelink library list.
pub const SHT_GNU_LIBLIST: u32 = 0x6ffffff7;
/// Checksum for DSO content.
pub const SHT_CHECKSUM: u32 = 0x6ffffff8;
/// Sun-specific low bound.
pub const SHT_LOSUNW: u32 = 0x6ffffffa;
pub const SHT_SUNW_MOVE: u32 = 0x6ffffffa;
pub const SHT_SUNW_COMDAT: u32 = 0x6ffffffb;
pub const SHT_SUNW_SYMINFO: u32 = 0x6ffffffc;
/// Version definition section.
pub const SHT_GNU_VERDEF: u32 = 0x6ffffffd;
/// Version needs section.
pub const SHT_GNU_VERNEED: u32 = 0x6ffffffe;
/// Version symbol table.
pub const SHT_GNU_VERSYM: u32 = 0x6fffffff;
/// Sun-specific high bound.
pub const SHT_HISUNW: u32 = 0x6fffffff;
/// End OS-specific type.
pub const SHT_HIOS: u32 = 0x6fffffff;
/// Start of processor-specific.
pub const SHT_LOPROC: u32 = 0x70000000;
/// End of processor-specific.
pub const SHT_HIPROC: u32 = 0x7fffffff;
/// Start of application-specific.
pub const SHT_LOUSER: u32 = 0x80000000;
/// End of application-specific.
pub const SHT_HIUSER: u32 = 0x8fffffff;

// Legal values for sh_flags (section flags)
/// Writable.
pub const SHF_WRITE: u32 = 1 << 0;
/// Occupies memory during execution.
pub const SHF_ALLOC: u32 = 1 << 1;
/// Executable.
pub const SHF_EXECINSTR: u32 = 1 << 2;
/// Might be merged.
pub const SHF_MERGE: u32 = 1 << 4;
/// Contains nul-terminated strings.
pub const SHF_STRINGS: u32 = 1 << 5;
/// `sh_info' contains SHT index.
pub const SHF_INFO_LINK: u32 = 1 << 6;
/// Preserve order after combining.
pub const SHF_LINK_ORDER: u32 = 1 << 7;
/// Non-standard OS specific handling required.
pub const SHF_OS_NONCONFORMING: u32 = 1 << 8;
/// Section is member of a group.
pub const SHF_GROUP: u32 = 1 << 9;
/// Section hold thread-local data.
pub const SHF_TLS: u32 = 1 << 10;
/// Section with compressed data.
pub const SHF_COMPRESSED: u32 = 1 << 11;
/// OS-specific..
pub const SHF_MASKOS: u32 = 0x0ff00000;
/// Processor-specific.
pub const SHF_MASKPROC: u32 = 0xf0000000;
/// Special ordering requirement (Solaris).
pub const SHF_ORDERED: u32 = 1 << 30;
// /// Section is excluded unless referenced or allocated (Solaris).
// pub const SHF_EXCLUDE: u32 = 1U << 31;

pub fn sht_to_str(sht: u32) -> &'static str {
    match sht {
        SHT_NULL => "SHT_NULL",
        SHT_PROGBITS => "SHT_PROGBITS",
        SHT_SYMTAB => "SHT_SYMTAB",
        SHT_STRTAB => "SHT_STRTAB",
        SHT_RELA => "SHT_RELA",
        SHT_HASH => "SHT_HASH",
        SHT_DYNAMIC => "SHT_DYNAMIC",
        SHT_NOTE => "SHT_NOTE",
        SHT_NOBITS => "SHT_NOBITS",
        SHT_REL => "SHT_REL",
        SHT_SHLIB => "SHT_SHLIB",
        SHT_DYNSYM => "SHT_DYNSYM",
        SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
        SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
        SHT_PREINIT_ARRAY => "SHT_PREINIT_ARRAY",
        SHT_GROUP => "SHT_GROUP",
        SHT_SYMTAB_SHNDX => "SHT_SYMTAB_SHNDX",
        SHT_NUM => "SHT_NUM",
        SHT_LOOS => "SHT_LOOS",
        SHT_GNU_ATTRIBUTES => "SHT_GNU_ATTRIBUTES",
        SHT_GNU_HASH => "SHT_GNU_HASH",
        SHT_GNU_LIBLIST => "SHT_GNU_LIBLIST",
        SHT_CHECKSUM => "SHT_CHECKSUM",
        SHT_SUNW_MOVE => "SHT_SUNW_MOVE",
        SHT_SUNW_COMDAT => "SHT_SUNW_COMDAT",
        SHT_SUNW_SYMINFO => "SHT_SUNW_SYMINFO",
        SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
        SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
        SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
        SHT_LOPROC => "SHT_LOPROC",
        SHT_HIPROC => "SHT_HIPROC",
        SHT_LOUSER => "SHT_LOUSER",
        SHT_HIUSER => "SHT_HIUSER",
        _ => "UNKNOWN_SHT",
    }
}

macro_rules! elf_section_header_from_bytes { () => {
        pub fn from_bytes(bytes: &[u8], shnum: usize) -> Vec<SectionHeader> {
            let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut SectionHeader, shnum) };
            let mut shdrs = Vec::with_capacity(shnum);
            shdrs.extend_from_slice(bytes);
            shdrs
        }};}

macro_rules! elf_section_header_from_raw_parts { () => {
        pub unsafe fn from_raw_parts<'a>(shdrp: *const SectionHeader,
                                         shnum: usize)
                                         -> &'a [SectionHeader] {
            slice::from_raw_parts(shdrp, shnum)
        }};}

macro_rules! elf_section_header_from_fd { () => {
        pub fn from_fd(fd: &mut File, offset: u64, count: usize) -> io::Result<Vec<SectionHeader>> {
            let mut shdrs = vec![0u8; count * SIZEOF_SHDR];
            try!(fd.seek(Start(offset)));
            try!(fd.read(&mut shdrs));
            Ok(SectionHeader::from_bytes(&shdrs, count))
        }
    };}

macro_rules! elf_section_header_from_endian { ($from_endian:item) => {
        #[cfg(feature = "endian_fd")]
        $from_endian
    };}

macro_rules! elf_section_header_impure_impl { ($header:item) => {

        #[cfg(feature = "std")]
        pub use self::impure::*;

        #[cfg(feature = "std")]
        mod impure {

            use super::*;

            use core::slice;
            use core::fmt;

            use std::fs::File;
            use std::io::{self, Read, Seek};
            use std::io::SeekFrom::Start;

            impl ElfSectionHeader for SectionHeader {
                /// Section name (string tbl index)
                fn sh_name(&self) -> usize {
                    self.sh_name as usize
                }
                /// Section type
                fn sh_type(&self) -> u32 {
                    self.sh_type
                }
                /// Section flags
                fn sh_flags(&self) -> u64 {
                    self.sh_flags as u64
                }
                /// Section virtual addr at execution
                fn sh_addr(&self) -> u64 {
                    self.sh_addr as u64
                }
                /// Section file offset
                fn sh_offset(&self) -> u64 {
                    self.sh_offset as u64
                }
                /// Section size in bytes
                fn sh_size(&self) -> u64 {
                    self.sh_size as u64
                }
                /// Link to another section
                fn sh_link(&self) -> u32 {
                    self.sh_link
                }
                /// Additional section information
                fn sh_info(&self) -> u32 {
                    self.sh_info
                }
                /// Section alignment
                fn sh_addralign(&self) -> u64 {
                    self.sh_addralign as u64
                }
                /// Entry size if section holds table
                fn sh_entsize(&self) -> u64 {
                    self.sh_entsize as u64
                }
            }

            impl fmt::Debug for SectionHeader {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f,
                           "sh_name: {} sh_type {} sh_flags: 0x{:x} sh_addr: 0x{:x} sh_offset: 0x{:x} \
                            sh_size: 0x{:x} sh_link: 0x{:x} sh_info: 0x{:x} sh_addralign 0x{:x} sh_entsize 0x{:x}",
                           self.sh_name,
                           sht_to_str(self.sh_type as u32),
                           self.sh_flags,
                           self.sh_addr,
                           self.sh_offset,
                           self.sh_size,
                           self.sh_link,
                           self.sh_info,
                           self.sh_addralign,
                           self.sh_entsize)
                }
            }
            $header
        }
    };}
