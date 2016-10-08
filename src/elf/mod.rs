//! Access ELF constants, other helper functions, which are independent of ELF bithood.  Also
//! provides simple parser which returns an Elf64 or Elf32 "pre-built" binary.
//!
//! **WARNING**: to use the automagic ELF datatype union parser, you _must_ enable both elf and
//! elf32 features - i.e., do not use `no_elf` **NOR** `no_elf32`, otherwise you'll get obscure
//! errors about [goblin::elf::from_fd](fn.from_fd.html) missing.

#[cfg(not(feature = "pure"))]
pub mod strtab;

// These are shareable values for the 32/64 bit implementations.
//
// They are publicly re-exported by the pub-using module
#[macro_use]
pub mod header {

    macro_rules! elf_header {
        ($size:ident) => {
            #[repr(C)]
            #[derive(Clone, Default)]
            pub struct Header {
                pub e_ident: [u8; SIZEOF_IDENT],
                pub e_type: u16,
                pub e_machine: u16,
                pub e_version: u32,
                pub e_entry: $size,
                pub e_phoff: $size,
                pub e_shoff: $size,
                pub e_flags: u32,
                pub e_ehsize: u16,
                pub e_phentsize: u16,
                pub e_phnum: u16,
                pub e_shentsize: u16,
                pub e_shnum: u16,
                pub e_shstrndx: u16,
            }
        }
    }

    /// No file type.
    pub const ET_NONE: u16 = 0;
    /// Relocatable file.
    pub const ET_REL: u16 = 1;
    /// Executable file.
    pub const ET_EXEC: u16 = 2;
    /// Shared object file.
    pub const ET_DYN: u16 = 3;
    /// Core file.
    pub const ET_CORE: u16 = 4;
    /// Number of defined types.
    pub const ET_NUM: u16 = 5;

    /// The ELF magic number.
    pub const ELFMAG: &'static [u8; 4] = b"\x7FELF";
    /// SELF (Security-enhanced ELF) magic number.
    pub const SELFMAG: usize = 4;

    /// File class byte index.
    pub const EI_CLASS: usize = 4;
    /// Invalid class.
    pub const ELFCLASSNONE: u8 = 0;
    /// 32-bit objects.
    pub const ELFCLASS32: u8 = 1;
    /// 64-bit objects.
    pub const ELFCLASS64: u8 = 2;
    /// ELF class number.
    pub const ELFCLASSNUM: u8 = 3;

    /// Data encoding byte index.
    pub const EI_DATA: usize = 5;
    /// Invalid data encoding.
    pub const ELFDATANONE: u8 = 0;
    /// 2's complement, little endian.
    pub const ELFDATA2LSB: u8 = 1;
    /// 2's complement, big endian.
    pub const ELFDATA2MSB: u8 = 2;
    /// Number of bytes in an identifier.
    pub const SIZEOF_IDENT: usize = 16;

    /// Convert an ET value to their associated string.
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
    pub use self::impure::*;

    #[cfg(not(feature = "pure"))]
    mod impure {
        use super::*;

        use std::fs::File;
        use std::io;
        use std::io::Read;
        use std::io::Seek;
        use std::io::SeekFrom::Start;

        /// Search forward in the stream.
        pub fn peek(fd: &mut File) -> io::Result<(u8, bool)> {
            let mut header = [0u8; SIZEOF_IDENT];
            try!(fd.seek(Start(0)));

            match try!(fd.read(&mut header)) {
                SIZEOF_IDENT => {
                    let class = header[EI_CLASS];
                    let is_lsb = header[EI_DATA] == ELFDATA2LSB;
                    Ok((class, is_lsb))
                }
                count => {
                    io_error!("Error: {:?} size is smaller than an ELF identication header",
                              count)
                }
            }
        }
    }

    /// Derive the `from_bytes` method for a header.
    macro_rules! elf_header_from_bytes {
        () => {
            /// Returns the corresponding ELF header from the given byte array.
            pub fn from_bytes(bytes: &[u8; SIZEOF_EHDR]) -> Header {
                // This is not unsafe because the header's size is encoded in the function,
                // although the header can be semantically invalid.
                let header: &Header = unsafe { mem::transmute(bytes) };
                header.clone()
            }
        };
    }

    /// Derive the `from_fd` method for a header.
    macro_rules! elf_header_from_fd {
        () => {
            /// Load a header from a file.
            #[cfg(feature = "no_endian_fd")]
            pub fn from_fd(fd: &mut File) -> io::Result<Header> {
                let mut elf_header = [0; SIZEOF_EHDR];
                try!(fd.read(&mut elf_header));
                Ok(Header::from_bytes(&elf_header))
            }
        };
    }

    macro_rules! elf_header_impure_impl {
        ($header:item) => {
            #[cfg(not(feature = "pure"))]
            pub use self::impure::*;

            #[cfg(not(feature = "pure"))]
            mod impure {

                use super::*;

                use std::mem;
                use std::fmt;
                use std::fs::File;
                use std::io::Read;
                use std::io;

                impl fmt::Debug for Header {
                    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        write!(f,
                               "e_ident: {:?} e_type: {} e_machine: 0x{:x} e_version: 0x{:x} e_entry: 0x{:x} \
                               e_phoff: 0x{:x} e_shoff: 0x{:x} e_flags: {:x} e_ehsize: {} e_phentsize: {} \
                            e_phnum: {} e_shentsize: {} e_shnum: {} e_shstrndx: {}",
                            self.e_ident,
                            et_to_str(self.e_type),
                            self.e_machine,
                            self.e_version,
                            self.e_entry,
                            self.e_phoff,
                            self.e_shoff,
                            self.e_flags,
                            self.e_ehsize,
                            self.e_phentsize,
                            self.e_phnum,
                            self.e_shentsize,
                            self.e_shnum,
                            self.e_shstrndx)
                    }
                }

                $header
            }
        };
    }
}

#[macro_use]
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

    macro_rules! elf_program_header_from_bytes { () => {
        pub fn from_bytes(bytes: &[u8], phnum: usize) -> Vec<ProgramHeader> {
            let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut ProgramHeader, phnum) };
            let mut phdrs = Vec::with_capacity(phnum);
            phdrs.extend_from_slice(bytes);
            phdrs
        }};}

    macro_rules! elf_program_header_from_raw_parts { () => {
        pub unsafe fn from_raw_parts<'a>(phdrp: *const ProgramHeader,
                                         phnum: usize)
                                         -> &'a [ProgramHeader] {
            slice::from_raw_parts(phdrp, phnum)
        }};}

    macro_rules! elf_program_header_from_fd { () => {
        #[cfg(feature = "no_endian_fd")]
        pub fn from_fd(fd: &mut File, offset: u64, count: usize, _: bool) -> io::Result<Vec<ProgramHeader>> {
            use std::io::Read;
            let mut phdrs = vec![0u8; count * SIZEOF_PHDR];
            try!(fd.seek(Start(offset)));
            try!(fd.read(&mut phdrs));
            Ok(ProgramHeader::from_bytes(&phdrs, count))
        }
    };}

    macro_rules! elf_program_header_from_fd_endian { ($from_fd_endian:item) => {
        #[cfg(not(feature = "no_endian_fd"))]
        $from_fd_endian
    };}

    macro_rules! elf_program_header_impure_impl { ($header:item) => {

        #[cfg(not(feature = "pure"))]
        pub use self::impure::*;

        #[cfg(not(feature = "pure"))]
        mod impure {

            use super::*;

            use std::slice;
            use std::fmt;
            use std::fs::File;
            use std::io::Seek;
            use std::io::SeekFrom::Start;
            use std::io;

            impl fmt::Debug for ProgramHeader {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f,
                           "p_type: {} p_flags 0x{:x} p_offset: 0x{:x} p_vaddr: 0x{:x} p_paddr: 0x{:x} \
                            p_filesz: 0x{:x} p_memsz: 0x{:x} p_align: {}",
                           pt_to_str(self.p_type),
                           self.p_flags,
                           self.p_offset,
                           self.p_vaddr,
                           self.p_paddr,
                           self.p_filesz,
                           self.p_memsz,
                           self.p_align)
                }
            }
            $header
        }
    };}
}

#[macro_use]
pub mod section_header {

    macro_rules! elf_section_header {
        ($size:ident) => {
            #[repr(C)]
            #[derive(Clone, PartialEq, Default)]
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
            //TODO: implement
            /*
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
            */
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
        #[cfg(feature = "no_endian_fd")]
        pub fn from_fd(fd: &mut File, offset: u64, count: usize, _: bool) -> io::Result<Vec<SectionHeader>> {
            use std::io::Read;
            let mut shdrs = vec![0u8; count * SIZEOF_SHDR];
            try!(fd.seek(Start(offset)));
            try!(fd.read(&mut shdrs));
            Ok(SectionHeader::from_bytes(&shdrs, count))
        }
    };}

    macro_rules! elf_section_header_from_fd_endian { ($from_fd_endian:item) => {
        #[cfg(not(feature = "no_endian_fd"))]
        $from_fd_endian
    };}

    macro_rules! elf_section_header_impure_impl { ($header:item) => {

        #[cfg(not(feature = "pure"))]
        pub use self::impure::*;

        #[cfg(not(feature = "pure"))]
        mod impure {

            use super::*;

            use std::slice;
            use std::fmt;
            use std::fs::File;
            use std::io::Seek;
            use std::io::SeekFrom::Start;
            use std::io;

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


}

#[macro_use]
pub mod sym {
    // === Sym bindings ===
    /// Local symbol.
    pub const STB_LOCAL: u8 = 0;
    /// Global symbol.
    pub const STB_GLOBAL: u8 = 1;
    /// Weak symbol.
    pub const STB_WEAK: u8 = 2;
    /// Number of defined types..
    pub const STB_NUM: u8 = 3;
    /// Start of OS-specific.
    pub const STB_LOOS: u8 = 10;
    /// Unique symbol..
    pub const STB_GNU_UNIQUE: u8 = 10;
    /// End of OS-specific.
    pub const STB_HIOS: u8 = 12;
    /// Start of processor-specific.
    pub const STB_LOPROC: u8 = 13;
    /// End of processor-specific.
    pub const STB_HIPROC: u8 = 15;
    /// === Sym types ===
    /// Symbol type is unspecified.
    pub const STT_NOTYPE: u8 = 0;
    /// Symbol is a data object.
    pub const STT_OBJECT: u8 = 1;
    /// Symbol is a code object.
    pub const STT_FUNC: u8 = 2;
    /// Symbol associated with a section.
    pub const STT_SECTION: u8 = 3;
    /// Symbol's name is file name.
    pub const STT_FILE: u8 = 4;
    /// Symbol is a common data object.
    pub const STT_COMMON: u8 = 5;
    /// Symbol is thread-local data object.
    pub const STT_TLS: u8 = 6;
    /// Number of defined types.
    pub const STT_NUM: u8 = 7;
    /// Start of OS-specific.
    pub const STT_LOOS: u8 = 10;
    /// Symbol is indirect code object.
    pub const STT_GNU_IFUNC: u8 = 10;
    /// End of OS-specific.
    pub const STT_HIOS: u8 = 12;
    /// Start of processor-specific.
    pub const STT_LOPROC: u8 = 13;
    /// End of processor-specific.
    pub const STT_HIPROC: u8 = 15;

    /// Get the ST binding.
    ///
    /// This is the first four bits of the byte.
    #[inline]
    pub fn st_bind(info: u8) -> u8 {
        info >> 4
    }

    /// Get the ST type.
    ///
    /// This is the last four bits of the byte.
    #[inline]
    pub fn st_type(info: u8) -> u8 {
        info & 0xf
    }

    /// Is this information defining an import?
    #[inline]
    pub fn is_import(info: u8, value: u8) -> bool {
        let binding = st_bind(info);
        binding == STB_GLOBAL && value == 0
    }

    /// Convenience function to get the &'static str type from the symbols `st_info`.
    pub fn get_type(info: u8) -> &'static str {
        type_to_str(st_type(info))
    }

    /// Get the string for some binding.
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

    /// Get the string for some type.
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

    macro_rules! elf_sym_impure_impl {
        ($from_fd_endian:item) => {

            #[cfg(not(feature = "pure"))]
            pub use self::impure::*;

            #[cfg(not(feature = "pure"))]
            mod impure {

                use std::fs::File;
                use std::io::Read;
                use std::io::Seek;
                use std::io::SeekFrom::Start;
                use std::io;
                use std::fmt;
                use std::slice;

                use super::*;

                impl fmt::Debug for Sym {
                    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        let bind = st_bind(self.st_info);
                        let typ = st_type(self.st_info);
                        write!(f,
                               "st_name: {} {} {} st_other: {} st_shndx: {} st_value: {:x} st_size: {}",
                               self.st_name,
                               bind_to_str(bind),
                               type_to_str(typ),
                               self.st_other,
                               self.st_shndx,
                               self.st_value,
                               self.st_size)
                    }
                }

                pub unsafe fn from_raw<'a>(symp: *const Sym, count: usize) -> &'a [Sym] {
                    slice::from_raw_parts(symp, count)
                }

                // TODO: this is broken, fix (not used often by me since don't have luxury of debug symbols usually)
                #[cfg(feature = "no_endian_fd")]
                pub fn from_fd<'a>(fd: &mut File, offset: usize, count: usize, _: bool) -> io::Result<Vec<Sym>> {
                    // TODO: AFAIK this shouldn't work, since i pass in a byte size...
                    let mut bytes = vec![0u8; count * SIZEOF_SYM];
                    try!(fd.seek(Start(offset as u64)));
                    try!(fd.read(&mut bytes));
                    let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut Sym, count) };
                    let mut syms = Vec::with_capacity(count);
                    syms.extend_from_slice(bytes);
                    syms.dedup();
                    Ok(syms)
                }

                #[cfg(not(feature = "no_endian_fd"))]
                $from_fd_endian

            }
        };
    }
}

#[macro_use]
pub mod dyn {
    // TODO: figure out what's the best, most friendly + safe API choice here - u32s or u64s
    // remember that DT_TAG is "pointer sized"/used as address sometimes Original rationale: I
    // decided to use u64 instead of u32 due to pattern matching use case seems safer to cast the
    // elf32's d_tag from u32 -> u64 at runtime instead of casting the elf64's d_tag from u64 ->
    // u32 at runtime
    // TODO: Documentation.
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

    /// Converts a tag to its string representation.
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
    /// Object may use DF_ORIGIN.
    pub const DF_ORIGIN: u64 = 0x00000001;
    /// Symbol resolutions starts here.
    pub const DF_SYMBOLIC: u64 = 0x00000002;
    /// Object contains text relocations.
    pub const DF_TEXTREL: u64 = 0x00000004;
    /// No lazy binding for this object.
    pub const DF_BIND_NOW: u64 = 0x00000008;
    /// Module uses the static TLS model.
    pub const DF_STATIC_TLS: u64 = 0x00000010;

    // State flags selectable in the `d_un.d_val` element of the DT_FLAGS_1 entry in the dynamic section.
    /// Set RTLD_NOW for this object.
    pub const DF_1_NOW: u64 = 0x00000001;
    /// Set RTLD_GLOBAL for this object.
    pub const DF_1_GLOBAL: u64 = 0x00000002;
    /// Set RTLD_GROUP for this object.
    pub const DF_1_GROUP: u64 = 0x00000004;
    /// Set RTLD_NODELETE for this object.
    pub const DF_1_NODELETE: u64 = 0x00000008;
    /// Trigger filtee loading at runtime.
    pub const DF_1_LOADFLTR: u64 = 0x00000010;
    /// Set RTLD_INITFIRST for this object.
    pub const DF_1_INITFIRST: u64 = 0x00000020;
    /// Set RTLD_NOOPEN for this object.
    pub const DF_1_NOOPEN: u64 = 0x00000040;
    /// $ORIGIN must be handled.
    pub const DF_1_ORIGIN: u64 = 0x00000080;
    /// Direct binding enabled.
    pub const DF_1_DIRECT: u64 = 0x00000100;
    pub const DF_1_TRANS: u64 = 0x00000200;
    /// Object is used to interpose.
    pub const DF_1_INTERPOSE: u64 = 0x00000400;
    /// Ignore default lib search path.
    pub const DF_1_NODEFLIB: u64 = 0x00000800;
    /// Object can't be dldump'ed.
    pub const DF_1_NODUMP: u64 = 0x00001000;
    /// Configuration alternative created.
    pub const DF_1_CONFALT: u64 = 0x00002000;
    /// Filtee terminates filters search.
    pub const DF_1_ENDFILTEE: u64 = 0x00004000;
    /// Disp reloc applied at build time.
    pub const DF_1_DISPRELDNE: u64 = 0x00008000;
    /// Disp reloc applied at run-time.
    pub const DF_1_DISPRELPND: u64 = 0x00010000;
    /// Object has no-direct binding.
    pub const DF_1_NODIRECT: u64 = 0x00020000;
    pub const DF_1_IGNMULDEF: u64 = 0x00040000;
    pub const DF_1_NOKSYMS: u64 = 0x00080000;
    pub const DF_1_NOHDR: u64 = 0x00100000;
    /// Object is modified after built.
    pub const DF_1_EDITED: u64 = 0x00200000;
    pub const DF_1_NORELOC: u64 = 0x00400000;
    /// Object has individual interposers.
    pub const DF_1_SYMINTPOSE: u64 = 0x00800000;
    /// Global auditing required.
    pub const DF_1_GLOBAUDIT: u64 = 0x01000000;
    /// Singleton symbols are used.
    pub const DF_1_SINGLETON: u64 = 0x02000000;

    macro_rules! elf_dyn_impure_impl {
        ($size:ident, $from_fd_endian:item) => {

            #[cfg(not(feature = "pure"))]
            pub use self::impure::*;

            #[cfg(not(feature = "pure"))]
            mod impure {

                use std::fs::File;
                use std::io::Seek;
                use std::io::SeekFrom::Start;
                use std::io;
                use std::fmt;
                use std::slice;
                use super::super::program_header::{ProgramHeader, PT_DYNAMIC};
                use super::super::super::elf::strtab::Strtab;

                use super::*;

                impl fmt::Debug for Dyn {
                    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        write!(f,
                               "d_tag: {} d_val: 0x{:x}",
                               tag_to_str(self.d_tag as u64),
                               self.d_val)
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

                #[cfg(feature = "no_endian_fd")]
                /// Returns a vector of dynamic entries from the given fd and program headers
                pub fn from_fd(mut fd: &File, phdrs: &[ProgramHeader], _: bool) -> io::Result<Option<Vec<Dyn>>> {
                    use std::io::Read;
                    for phdr in phdrs {
                        if phdr.p_type == PT_DYNAMIC {
                            let filesz = phdr.p_filesz as usize;
                            let dync = filesz / SIZEOF_DYN;
                            let mut bytes = vec![0u8; filesz];
                            try!(fd.seek(Start(phdr.p_offset as u64)));
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
                pub unsafe fn from_raw<'a>(bias: $size, vaddr: $size) -> &'a [Dyn] {
                    let dynp = vaddr.wrapping_add(bias) as *const Dyn;
                    let mut idx = 0;
                    while (*dynp.offset(idx)).d_tag as u64 != DT_NULL {
                        idx += 1;
                    }
                    slice::from_raw_parts(dynp, idx as usize)
                }

                // TODO: these bare functions have always seemed awkward, but not sure where they should go...

                /// Maybe gets and returns the dynamic array with the same lifetime as the [phdrs], using the provided bias with wrapping addition.
                /// If the bias is wrong, it will either segfault or give you incorrect values, beware
                pub unsafe fn from_phdrs(bias: $size, phdrs: &[ProgramHeader]) -> Option<&[Dyn]> {
                    for phdr in phdrs {
                        // FIXME: change to casting to u64 similar to DT_*?
                        if phdr.p_type as u32 == PT_DYNAMIC {
                            return Some(from_raw(bias, phdr.p_vaddr));
                        }
                    }
                    None
                }

                /// Gets the needed libraries from the `_DYNAMIC` array, with the str slices lifetime tied to the dynamic array/strtab's lifetime(s)
                pub unsafe fn get_needed<'a>(dyns: &[Dyn], strtab: *const Strtab<'a>, count: usize) -> Vec<&'a str> {
                    let mut needed = Vec::with_capacity(count);
                    for dyn in dyns {
                        if dyn.d_tag as u64 == DT_NEEDED {
                            let lib = &(*strtab)[dyn.d_val as usize];
                            needed.push(lib);
                        }
                    }
                    needed
                }

                #[cfg(not(feature = "no_endian_fd"))]
                /// Returns a vector of dynamic entries from the given fd and program headers
                $from_fd_endian

            }

            /// Important dynamic linking info generated via a single pass through the _DYNAMIC array
            #[derive(Default)]
            pub struct DynamicInfo {
                pub rela: usize,
                pub relasz: usize,
                pub relaent: $size,
                pub relacount: usize,
                pub gnu_hash: Option<$size>,
                pub hash: Option<$size>,
                pub strtab: usize,
                pub strsz: usize,
                pub symtab: usize,
                pub syment: usize,
                pub pltgot: Option<$size>,
                pub pltrelsz: usize,
                pub pltrel: $size,
                pub jmprel: usize,
                pub verneed: $size,
                pub verneednum: $size,
                pub versym: $size,
                pub init: $size,
                pub fini: $size,
                pub init_array: $size,
                pub init_arraysz: usize,
                pub fini_array: $size,
                pub fini_arraysz: usize,
                pub needed_count: usize,
                pub flags: $size,
                pub flags_1: $size,
                pub soname: usize,
            }

            impl DynamicInfo {
                pub fn new(dynamic: &[Dyn], bias: usize) -> DynamicInfo {
                    let mut res = DynamicInfo::default();

                    for dyn in dynamic {
                        match dyn.d_tag as u64 {
                            DT_RELA => res.rela = dyn.d_val.wrapping_add(bias as _) as usize, // .rela.dyn
                            DT_RELASZ => res.relasz = dyn.d_val as usize,
                            DT_RELAENT => res.relaent = dyn.d_val as _,
                            DT_RELACOUNT => res.relacount = dyn.d_val as usize,
                            DT_GNU_HASH => res.gnu_hash = Some(dyn.d_val.wrapping_add(bias as _)),
                            DT_HASH => res.hash = Some(dyn.d_val.wrapping_add(bias as _)) as _,
                            DT_STRTAB => res.strtab = dyn.d_val.wrapping_add(bias as _) as usize,
                            DT_STRSZ => res.strsz = dyn.d_val as usize,
                            DT_SYMTAB => res.symtab = dyn.d_val.wrapping_add(bias as _) as usize,
                            DT_SYMENT => res.syment = dyn.d_val as usize,
                            DT_PLTGOT => res.pltgot = Some(dyn.d_val.wrapping_add(bias as _)) as _,
                            DT_PLTRELSZ => res.pltrelsz = dyn.d_val as usize,
                            DT_PLTREL => res.pltrel = dyn.d_val as _,
                            DT_JMPREL => res.jmprel = dyn.d_val.wrapping_add(bias as _) as usize, // .rela.plt
                            DT_VERNEED => res.verneed = dyn.d_val.wrapping_add(bias as _) as _,
                            DT_VERNEEDNUM => res.verneednum = dyn.d_val as _,
                            DT_VERSYM => res.versym = dyn.d_val.wrapping_add(bias as _) as _,
                            DT_INIT => res.init = dyn.d_val.wrapping_add(bias as _) as _,
                            DT_FINI => res.fini = dyn.d_val.wrapping_add(bias as _) as _,
                            DT_INIT_ARRAY => res.init_array = dyn.d_val.wrapping_add(bias as _) as _,
                            DT_INIT_ARRAYSZ => res.init_arraysz = dyn.d_val as _,
                            DT_FINI_ARRAY => res.fini_array = dyn.d_val.wrapping_add(bias as _) as _,
                            DT_FINI_ARRAYSZ => res.fini_arraysz = dyn.d_val as _,
                            DT_NEEDED => res.needed_count += 1,
                            DT_FLAGS => res.flags = dyn.d_val as _,
                            DT_FLAGS_1 => res.flags_1 = dyn.d_val as _,
                            DT_SONAME => res.soname = dyn.d_val as _,
                            _ => (),
                        }
                    }

                    res
                }
            }
        };
    }
}

#[macro_use]
pub mod rela {
    /// No reloc.
    pub const R_X86_64_NONE: u64 = 0;
    /// Direct 64 bit.
    pub const R_X86_64_64: u64 = 1;
    /// PC relative 32 bit signed.
    pub const R_X86_64_PC32: u64 = 2;
    /// 32 bit GOT entry.
    pub const R_X86_64_GOT32: u64 = 3;
    /// 32 bit PLT address.
    pub const R_X86_64_PLT32: u64 = 4;
    /// Copy symbol at runtime.
    pub const R_X86_64_COPY: u64 = 5;
    /// Create GOT entry.
    pub const R_X86_64_GLOB_DAT: u64 = 6;
    /// Create PLT entry.
    pub const R_X86_64_JUMP_SLOT: u64 = 7;
    /// Adjust by program base.
    pub const R_X86_64_RELATIVE: u64 = 8;
    /// 32 bit signed PC relative offset to GOT.
    pub const R_X86_64_GOTPCREL: u64 = 9;
    /// Direct 32 bit zero extended.
    pub const R_X86_64_32: u64 = 10;
    /// Direct 32 bit sign extended.
    pub const R_X86_64_32S: u64 = 11;
    /// Direct 16 bit zero extended.
    pub const R_X86_64_16: u64 = 12;
    /// 16 bit sign extended pc relative.
    pub const R_X86_64_PC16: u64 = 13;
    /// Direct 8 bit sign extended.
    pub const R_X86_64_8: u64 = 14;
    /// 8 bit sign extended pc relative.
    pub const R_X86_64_PC8: u64 = 15;
    /// ID of module containing symbol.
    pub const R_X86_64_DTPMOD64: u64 = 16;
    /// Offset in module's TLS block.
    pub const R_X86_64_DTPOFF64: u64 = 17;
    /// Offset in initial TLS block.
    pub const R_X86_64_TPOFF64: u64 = 18;
    /// 32 bit signed PC relative offset to two GOT entries for GD symbol.
    pub const R_X86_64_TLSGD: u64 = 19;
    /// 32 bit signed PC relative offset to two GOT entries for LD symbol.
    pub const R_X86_64_TLSLD: u64 = 20;
    /// Offset in TLS block.
    pub const R_X86_64_DTPOFF32: u64 = 21;
    /// 32 bit signed PC relative offset to GOT entry for IE symbol.
    pub const R_X86_64_GOTTPOFF: u64 = 22;
    /// Offset in initial TLS block.
    pub const R_X86_64_TPOFF32: u64 = 23;
    /// PC relative 64 bit.
    pub const R_X86_64_PC64: u64 = 24;
    /// 64 bit offset to GOT.
    pub const R_X86_64_GOTOFF64: u64 = 25;
    /// 32 bit signed pc relative offset to GOT.
    pub const R_X86_64_GOTPC32: u64 = 26;
    /// 64-bit GOT entry offset.
    pub const R_X86_64_GOT64: u64 = 27;
    /// 64-bit PC relative offset to GOT entry.
    pub const R_X86_64_GOTPCREL64: u64 = 28;
    /// 64-bit PC relative offset to GOT.
    pub const R_X86_64_GOTPC64: u64 = 29;
    /// like GOT64, says PLT entry needed.
    pub const R_X86_64_GOTPLT64: u64 = 30;
    /// 64-bit GOT relative offset to PLT entry.
    pub const R_X86_64_PLTOFF64: u64 = 31;
    /// Size of symbol plus 32-bit addend.
    pub const R_X86_64_SIZE32: u64 = 32;
    /// Size of symbol plus 64-bit addend.
    pub const R_X86_64_SIZE64: u64 = 33;
    /// GOT offset for TLS descriptor..
    pub const R_X86_64_GOTPC32_TLSDESC: u64 = 34;
    /// Marker for call through TLS descriptor..
    pub const R_X86_64_TLSDESC_CALL: u64 = 35;
    /// TLS descriptor..
    pub const R_X86_64_TLSDESC: u64 = 36;
    /// Adjust indirectly by program base.
    pub const R_X86_64_IRELATIVE: u64 = 37;
    /// 64-bit adjust by program base.
    pub const R_X86_64_RELATIVE64: u64 = 38;
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

    macro_rules! elf_rela_impure_impl { ($from_fd_endian:item) => {

        #[cfg(not(feature = "pure"))]
        pub use self::impure::*;

        #[cfg(not(feature = "pure"))]
        mod impure {

            use super::*;

            use std::fs::File;
            use std::io::Seek;
            use std::io::SeekFrom::Start;
            use std::io;
            use std::fmt;
            use std::slice;

            impl fmt::Debug for Rela {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    let sym = r_sym(self.r_info);
                    let typ = r_type(self.r_info);
                    write!(f,
                           "r_offset: {:x} {} @ {} r_addend: {:x}",
                           self.r_offset,
                           type_to_str(typ as u64),
                           sym,
                           self.r_addend)
                }
            }

    /// Gets the rela entries given a rela u64 and the _size_ of the rela section in the binary, in bytes.  Works for regular rela and the pltrela table.
    /// Assumes the pointer is valid and can safely return a slice of memory pointing to the relas because:
    /// 1. `rela` points to memory received from the kernel (i.e., it loaded the executable), _or_
    /// 2. The binary has already been mmapped (i.e., it's a `SharedObject`), and hence it's safe to return a slice of that memory.
    /// 3. Or if you obtained the pointer in some other lawful manner
            pub unsafe fn from_raw<'a>(ptr: *const Rela, size: usize) -> &'a [Rela] {
                slice::from_raw_parts(ptr, size / SIZEOF_RELA)
            }

            #[cfg(feature = "no_endian_fd")]
            pub fn from_fd(fd: &mut File, offset: usize, size: usize, _: bool) -> io::Result<Vec<Rela>> {
                use std::io::Read;
                let count = size / SIZEOF_RELA;
                let mut bytes = vec![0u8; size];
                try!(fd.seek(Start(offset as u64)));
                try!(fd.read(&mut bytes));
                let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr() as *mut Rela, count) };
                let mut res = Vec::with_capacity(count);
                res.extend_from_slice(bytes);
                Ok(res)
            }

            #[cfg(not(feature = "no_endian_fd"))]
            $from_fd_endian
        }
    };}
}

#[cfg(all(not(feature = "pure"), not(feature = "no_elf32"), not(feature = "no_elf")))]
pub use self::impure::*;

#[cfg(all(not(feature = "pure"), not(feature = "no_elf32"), not(feature = "no_elf")))]
#[macro_use]
mod impure {

    use std::fs::File;
    use std::io;
    // use std::io::Read;
    // use std::io::SeekFrom::Start;

    use super::header;

    use super::super::elf32;
    use super::super::elf64;

    #[derive(Debug)]
    pub enum Binary {
        Elf32(elf32::Binary),
        Elf64(elf64::Binary),
    }

    pub fn from_fd(fd: &mut File) -> io::Result<Binary> {
        match try!(header::peek(fd)) {
            (header::ELFCLASS64, _is_lsb) => Ok(Binary::Elf64(try!(elf64::Binary::from_fd(fd)))),
            (header::ELFCLASS32, _is_lsb) => Ok(Binary::Elf32(try!(elf32::Binary::from_fd(fd)))),
            (class, is_lsb) => {
                io_error!("Unknown values in ELF ident header: class: {} is_lsb: {}",
                          class,
                          is_lsb)
            }
        }
    }
}

macro_rules! elf_from_fd { ($intmax:expr) => {
    use std::path::Path;
    use std::fs::File;
    use std::io;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom::Start;

    pub use super::super::elf::strtab;
    use super::{header, program_header, section_header, dyn, sym, rela};

    #[derive(Debug)]
    pub struct Binary {
        pub header: header::Header,
        pub program_headers: Vec<program_header::ProgramHeader>,
        pub section_headers: Vec<section_header::SectionHeader>,
        pub shdr_strtab: strtab::Strtab<'static>,
        pub dynamic: Option<Vec<dyn::Dyn>>,
        pub dynsyms: Vec<sym::Sym>,
        pub dynstrtab: strtab::Strtab<'static>,
        pub syms: Vec<sym::Sym>,
        pub strtab: strtab::Strtab<'static>,
        pub rela: Vec<rela::Rela>,
        pub pltrela: Vec<rela::Rela>,
        pub soname: Option<String>,
        pub interpreter: Option<String>,
        pub libraries: Vec<String>,
        pub is_lib: bool,
        pub size: usize,
        pub entry: usize,
    }

    impl Binary {
        pub fn from_fd (fd: &mut File) -> io::Result<Binary> {
            let header = try!(header::Header::from_fd(fd));
            let entry = header.e_entry as usize;
            let is_lib = header.e_type == header::ET_DYN;
            let is_lsb = header.e_ident[header::EI_DATA] == header::ELFDATA2LSB;

            let program_headers = try!(program_header::ProgramHeader::from_fd(fd, header.e_phoff as u64, header.e_phnum as usize, is_lsb));

            let dynamic = try!(dyn::from_fd(fd, &program_headers, is_lsb));
            let mut bias: usize = 0;
            for ph in &program_headers {
                if ph.p_type == program_header::PT_LOAD {
// this is an overflow hack that allows us to use virtual memory addresses as though they're in the file by generating a fake load bias which is then used to overflow the values in the dynamic array, and in a few other places (see Dyn::DynamicInfo), to generate actual file offsets; you may have to marinate a bit on why this works. i am unsure whether it works in every conceivable case. i learned this trick from reading too much dynamic linker C code (a whole other class of C code) and having to deal with broken older kernels on VMs. enjoi
                    bias = (($intmax - ph.p_vaddr).wrapping_add(1)) as usize;
                    break;
                }
            }

            let mut interpreter = None;
            for ph in &program_headers {
                if ph.p_type == program_header::PT_INTERP {
                    let mut bytes = vec![0u8; (ph.p_filesz - 1) as usize];
                    try!(fd.seek(Start(ph.p_offset as u64)));
                    try!(fd.read(&mut bytes));
                    interpreter = Some(String::from_utf8(bytes).unwrap())
                }
            }

            println!("header: 0x{:x}, header.e_shnum: {}", header.e_shoff, header.e_shnum);

            let section_headers = try!(section_header::SectionHeader::from_fd(fd, header.e_shoff as u64, header.e_shnum as usize, is_lsb));

            let mut syms = vec![];
            let mut strtab = strtab::Strtab::default();
            for shdr in &section_headers {
                if shdr.sh_type as u32 == section_header::SHT_SYMTAB {
                    let count = shdr.sh_size / shdr.sh_entsize;
                    syms = try!(sym::from_fd(fd, shdr.sh_offset as usize, count as usize, is_lsb))
                }
                if shdr.sh_type as u32 == section_header::SHT_STRTAB {
                    strtab = try!(strtab::Strtab::from_fd(fd, shdr.sh_offset as usize, shdr.sh_size as usize));
                }
            }

            let strtab_idx = header.e_shstrndx as usize;
            let shdr_strtab = if strtab_idx >= section_headers.len() {
                strtab::Strtab::default()
            } else {
                let shdr = &section_headers[strtab_idx];
                try!(strtab::Strtab::from_fd(fd, shdr.sh_offset as usize, shdr.sh_size as usize))
            };

            let mut soname = None;
            let mut libraries = vec![];
            let mut dynsyms = vec![];
            let mut rela = vec![];
            let mut pltrela = vec![];
            let mut dynstrtab = strtab::Strtab::default();
            if let Some(ref dynamic) = dynamic {
                let dyn_info = dyn::DynamicInfo::new(&dynamic, bias); // we explicitly overflow the values here with our bias
                dynstrtab = try!(strtab::Strtab::from_fd(fd,
                                                          dyn_info.strtab,
                                                          dyn_info.strsz));

                if dyn_info.soname != 0 {
                    soname = Some(dynstrtab.get(dyn_info.soname).to_owned())
                }
                if dyn_info.needed_count > 0 {
                    let needed = unsafe { dyn::get_needed(dynamic, &dynstrtab, dyn_info.needed_count)};
                    libraries = Vec::with_capacity(dyn_info.needed_count);
                    for lib in needed {
                        libraries.push(lib.to_owned());
                    }
                }

                let num_syms = (dyn_info.strtab - dyn_info.symtab) / dyn_info.syment;
                dynsyms = try!(sym::from_fd(fd, dyn_info.symtab, num_syms, is_lsb));
                rela = try!(rela::from_fd(fd, dyn_info.rela, dyn_info.relasz, is_lsb));
                pltrela = try!(rela::from_fd(fd, dyn_info.jmprel, dyn_info.pltrelsz, is_lsb));
            }

            let elf = Binary {
                header: header,
                program_headers: program_headers,
                section_headers: section_headers,
                shdr_strtab: shdr_strtab,
                dynamic: dynamic,
                dynsyms: dynsyms,
                dynstrtab: dynstrtab,
                syms: syms,
                strtab: strtab,
                rela: rela,
                pltrela: pltrela,
                soname: soname,
                interpreter: interpreter,
                libraries: libraries,
                is_lib: is_lib,
                size: fd.metadata().unwrap().len() as usize,
                entry: entry,
            };

            Ok(elf)
        }

        pub fn from_path(path: &Path) -> io::Result<Binary> {
            let mut fd = try!(File::open(&path));
            let metadata = fd.metadata().unwrap();
            if metadata.len() < header::SIZEOF_EHDR as u64 {
                io_error!("Error: {:?} size is smaller than an ELF header", path.as_os_str())
            } else {
                Self::from_fd(&mut fd)
            }
        }
    }
};}
