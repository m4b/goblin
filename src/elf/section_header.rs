macro_rules! elf_section_header {
    ($size:ident) => {
        #[repr(C)]
        #[derive(Copy, Clone, Eq, PartialEq, Default)]
        #[cfg_attr(feature = "std", derive(Pread, Pwrite, SizeWith))]
        /// Section Headers are typically used by humans and static linkers for additional information or how to relocate the object
        ///
        /// **NOTE** section headers are strippable from a binary without any loss of portability/executability; _do not_ rely on them being there!
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

        use plain;
        // Declare that this is a plain type.
        unsafe impl plain::Plain for SectionHeader {}

        impl ::core::fmt::Debug for SectionHeader {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
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

macro_rules! elf_section_header_std_impl { ($size:ty) => {

    #[cfg(test)]
    mod test {
        use super::*;
        #[test]
        fn size_of() {
            assert_eq!(::std::mem::size_of::<SectionHeader>(), SIZEOF_SHDR);
        }
    }

    #[cfg(feature = "std")]
    pub use self::std::*;

    #[cfg(feature = "std")]
    mod std {

        use elf::section_header::SectionHeader as ElfSectionHeader;
        use super::*;
        use elf::error::*;

        use std::fs::File;
        use std::io::{Read, Seek};
        use std::io::SeekFrom::Start;

        use plain::Methods;

        impl From<SectionHeader> for ElfSectionHeader {
            fn from(sh: SectionHeader) -> Self {
                ElfSectionHeader {
                    sh_name: sh.sh_name as usize,
                    sh_type: sh.sh_type,
                    sh_flags: sh.sh_flags   as u64,
                    sh_addr: sh.sh_addr     as u64,
                    sh_offset: sh.sh_offset as u64,
                    sh_size: sh.sh_size     as u64,
                    sh_link: sh.sh_link,
                    sh_info: sh.sh_info,
                    sh_addralign: sh.sh_addralign as u64,
                    sh_entsize: sh.sh_entsize as u64,
                }
            }
        }
        impl From<ElfSectionHeader> for SectionHeader {
            fn from(sh: ElfSectionHeader) -> Self {
                SectionHeader {
                    sh_name     : sh.sh_name as u32,
                    sh_type     : sh.sh_type,
                    sh_flags    : sh.sh_flags as $size,
                    sh_addr     : sh.sh_addr as $size,
                    sh_offset   : sh.sh_offset as $size,
                    sh_size     : sh.sh_size as $size,
                    sh_link     : sh.sh_link,
                    sh_info     : sh.sh_info,
                    sh_addralign: sh.sh_addralign as $size,
                    sh_entsize  : sh.sh_entsize as $size,
                }
            }
        }

        impl SectionHeader {
            pub fn from_bytes(bytes: &[u8], shnum: usize) -> Vec<SectionHeader> {
                let mut shdrs = vec![SectionHeader::default(); shnum];
                // FIXME: copy_from_slice() panics if the slices are not equal length
                shdrs.as_mut_bytes().copy_from_slice(bytes);
                shdrs
            }

            pub fn from_fd(fd: &mut File, offset: u64, shnum: usize) -> Result<Vec<SectionHeader>> {
                let mut shdrs = vec![SectionHeader::default(); shnum];
                try!(fd.seek(Start(offset)));
                try!(fd.read(shdrs.as_mut_bytes()));
                Ok(shdrs)
            }
        }
    }
};}


pub mod section_header32 {
    pub use elf::section_header::*;

    elf_section_header!(u32);

    pub const SIZEOF_SHDR: usize = 40;

    elf_section_header_std_impl!(u32);
}


pub mod section_header64 {

    pub use elf::section_header::*;

    elf_section_header!(u64);

    pub const SIZEOF_SHDR: usize = 64;

    elf_section_header_std_impl!(u64);
}

///////////////////////////////
// Std/analysis/Unified Structs
///////////////////////////////

#[cfg(feature = "std")]
pub use self::std::*;

#[cfg(feature = "std")]
mod std {
    use super::*;
    use core::fmt;
    use core::result;
    use scroll::{self, ctx};
    use container::{Container, Ctx};

    #[derive(Default, PartialEq, Clone)]
    /// A unified SectionHeader - convertable to and from 32-bit and 64-bit variants
    pub struct SectionHeader {
        /// Section name (string tbl index)
        pub sh_name: usize,
        /// Section type
        pub sh_type: u32,
        /// Section flags
        pub sh_flags: u64,
        /// Section virtual addr at execution
        pub sh_addr: u64,
        /// Section file offset
        pub sh_offset: u64,
        /// Section size in bytes
        pub sh_size: u64,
        /// Link to another section
        pub sh_link: u32,
        /// Additional section information
        pub sh_info: u32,
        /// Section alignment
        pub sh_addralign: u64,
        /// Entry size if section holds table
        pub sh_entsize: u64,
    }

    impl SectionHeader {
        pub fn new() -> Self {
            SectionHeader {
                sh_name: 0,
                sh_type: SHT_PROGBITS,
                sh_flags: SHF_ALLOC as u64,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 2 << 8,
                sh_entsize: 0,
            }
        }
        #[cfg(feature = "endian_fd")]
        pub fn parse<S: AsRef<[u8]>>(buffer: &S, mut offset: usize, count: usize, ctx: Ctx) -> ::error::Result<Vec<SectionHeader>> {
            use scroll::Gread;
            let mut section_headers = Vec::with_capacity(count);
            for _ in 0..count {
                let shdr = buffer.gread_with(&mut offset, ctx)?;
                section_headers.push(shdr);
            }
            Ok(section_headers)
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

    impl ctx::SizeWith<Ctx> for SectionHeader {
        type Units = usize;
        fn size_with( &Ctx { container, .. }: &Ctx) -> Self::Units {
            match container {
                Container::Little => {
                    section_header32::SIZEOF_SHDR
                },
                Container::Big => {
                    section_header64::SIZEOF_SHDR
                },
            }
        }
    }

    impl<'a> ctx::TryFromCtx<'a, (usize, Ctx)> for SectionHeader {
        type Error = scroll::Error;
        fn try_from_ctx(buffer: &'a [u8], (offset, Ctx { container, le }): (usize, Ctx)) -> result::Result<Self, Self::Error> {
            use scroll::Pread;
            let shdr = match container {
                Container::Little => {
                    buffer.pread_with::<section_header32::SectionHeader>(offset, le)?.into()
                },
                Container::Big => {
                    buffer.pread_with::<section_header64::SectionHeader>(offset, le)?.into()
                }
            };
            Ok(shdr)
        }
    }

    impl ctx::TryIntoCtx<(usize, Ctx)> for SectionHeader {
        type Error = scroll::Error;
        fn try_into_ctx(self, mut buffer: &mut [u8], (offset, Ctx { container, le }): (usize, Ctx)) -> result::Result<(), Self::Error> {
            use scroll::Pwrite;
            match container {
                Container::Little => {
                    let shdr: section_header32::SectionHeader = self.into();
                    buffer.pwrite_with(shdr, offset, le)?;
                },
                Container::Big => {
                    let shdr: section_header64::SectionHeader = self.into();
                    buffer.pwrite_with(shdr, offset, le)?;
                }
            }
            Ok(())
        }
    }
}
