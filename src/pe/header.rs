use crate::error;
use crate::pe::{optional_header, section_table, symbol};
use crate::strtab;
use alloc::vec::Vec;
use log::debug;
use scroll::{ctx, IOread, IOwrite, Pread, Pwrite, SizeWith};

/// In `winnt.h` and `pe.h`, it's `IMAGE_DOS_HEADER`. It's a DOS header present in all PE binaries.
///
/// The DOS header is a relic from the MS-DOS era. It used to be useful to display an
/// error message if the binary is run in MS-DOS. Nowadays, only two fields from
/// the DOS header are used on Windows: [`signature` (aka `e_magic`)](DosHeader::signature)
/// and [`pe_pointer` (aka `e_lfanew`)](DosHeader::pe_pointer).
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pwrite)]
#[doc(alias("IMAGE_DOS_HEADER"))]
pub struct DosHeader {
    /// Magic number: `[0x5A, 0x4D]` (if read in little endian [ASCII](https://en.wikipedia.org/wiki/ASCII), "MZ" for [Mark Zbikowski](https://en.wikipedia.org/wiki/Mark_Zbikowski)).
    ///
    /// ## Non-MZ DOS executables
    ///
    /// * For [IBM OS/2](https://www.britannica.com/technology/IBM-OS-2), the value was "NE".
    /// * For IBM OS/2 LE, the value was "LE".
    /// * For [NT](https://en.wikipedia.org/wiki/Windows_NT), the value was "PE00".
    ///
    /// Sources:
    ///
    /// * <https://stixproject.github.io/data-model/1.2/WinExecutableFileObj/DOSHeaderType/>
    /// * <https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail>
    #[doc(alias("e_magic"))]
    pub signature: u16,
    /// In `winnt.h` and `pe.h`, it's `e_cblp`.
    ///
    /// It used to specify the number of bytes actually used in the last "page".
    /// Page used to refer to a segment of memory, usually of 512 bytes size.
    ///
    /// The case of full page was represented by 0x0000 (since the last page is never empty).
    ///
    /// For example, assuming a page size of 512 bytes, this value would
    /// be 0x0000 for a 1024 byte file, and 0x0001 for a 1025 byte file
    /// (since it only contains one valid byte).
    /// [Source](https://stixproject.github.io/data-model/1.2/WinExecutableFileObj/DOSHeaderType/).
    ///
    /// Typically, this field is set to 0. [Source](https://offwhitesecurity.dev/malware-development/portable-executable-pe/dos-header/).
    #[doc(alias("e_cblp"))]
    pub bytes_on_last_page: u16,
    /// In `winnt.h` and `pe.h`, it's `e_cp`.
    ///
    /// It used to specify the number of pages required to hold a file. For example,
    /// if the file contained 1024 bytes, and the file had pages of a size of 512 bytes,
    /// this [word](https://en.wikipedia.org/wiki/Word_(computer_architecture)) would contain
    /// 0x0002 (2 pages); if the file contained 1025 bytes, this word would contain 0x0003 (3 pages).
    /// [Source](https://stixproject.github.io/data-model/1.2/WinExecutableFileObj/DOSHeaderType/).
    ///
    /// Typically, this field is set to 0. [Source](https://offwhitesecurity.dev/malware-development/portable-executable-pe/dos-header/).
    #[doc(alias("e_cp"))]
    pub pages_in_file: u16,
    /// In `winnt.h` and `pe.h`, it's `e_crlc`.
    ///
    /// It used to specify the number of "relocation items", i.e. the number of entries that
    /// existed in the "relocation pointer table". If there were no relocations, this field
    /// would contain 0x0000.
    /// [Source](https://stixproject.github.io/data-model/1.2/WinExecutableFileObj/DOSHeaderType/).
    ///
    /// ## On relocation items and relocation pointer table
    ///
    /// When a program is compiled, memory addresses are often hard-coded into the binary code.
    /// These addresses are usually relative to the base address where the program expects to be loaded into memory.
    /// However, when the program is loaded into memory, it might not be loaded at its preferred base address due to
    /// various reasons such as memory fragmentation or other programs already occupying that space.
    ///
    /// Relocation items, also known as fixups or relocations, are pieces of data embedded within the executable file
    /// that indicate which memory addresses need to be adjusted when the program is loaded at a different base address.
    /// These relocations specify the location and type of adjustment needed.
    ///
    /// The relocation pointer table is a data structure that contains pointers to the locations within the executable file
    /// where relocations need to be applied. It allows the operating system's loader to efficiently locate and process the
    /// relocation data during the loading process.
    ///
    /// ---
    ///
    /// Typically, this field is set to 0. [Source](https://offwhitesecurity.dev/malware-development/portable-executable-pe/dos-header/).
    #[doc(alias("e_crlc"))]
    pub relocations: u16,
    /// In `winnt.h` and `pe.h`, it's `e_cparhdr`.
    ///
    /// It used to specify the size of the "executable header" in terms of "paragraphs" (16 byte chunks). It used to indicate
    /// the offset of the program's compiled/assembled and linked image (the load module) within the executable file. The size
    /// of the load module could have been deduced by substructing this value (converted to bytes) from the overall size that could
    /// have been derived from combining the value of [`pages_in_file` (aka `e_cp`)](DosHeader::pages_in_file) and the value of
    /// [`bytes_on_last_page` (aka `e_cblp)`](DosHeader::bytes_on_last_page). The header used to always span an even number of
    /// paragraphs.
    /// [Source](https://stixproject.github.io/data-model/1.2/WinExecutableFileObj/DOSHeaderType/).
    ///
    /// The "executable header" in this context refers to the DOS header itself.
    ///
    /// Typically, this field is set to 4. [Source](https://offwhitesecurity.dev/malware-development/portable-executable-pe/dos-header/).
    /// This is because the DOS header is 64 bytes long, and 64 / 16 = 4.
    #[doc(alias("e_cparhdr"))]
    pub size_of_header_in_paragraphs: u16,
    /// In `winnt.h` and `pe.h`, it's `e_minalloc`.
    ///
    /// It used to specify the minimum number of extra paragraphs needed to be allocated to begin execution. This is
    /// **in addition** to the memory required to hold the load module. This value normally represented the total size
    /// of any uninitialized data and/or stack segments that were linked at the end of the program. This space was not
    /// directly included in the load module, since there were no particular initializing values and it would simply waste
    /// disk space.
    ///
    /// Typically, this field is set to 0x10. [Source](https://offwhitesecurity.dev/malware-development/portable-executable-pe/dos-header/).
    #[doc(alias("e_minalloc"))]
    pub minimum_extra_paragraphs_needed: u16,
    /// In `winnt.h` and `pe.h`, it's `e_maxalloc`.
    ///
    /// It used to specify the maximum number of extra paragraphs needed to be allocated by to begin execution. This indicated
    /// **additional** memory over and above that required by the load module and the value specified in
    /// [`minimum_extra_paragraphs_needed` (aka `e_minalloc`)](DosHeader::minimum_extra_paragraphs_needed).
    /// If the request could not be satisfied, the program would be allocated as much memory as available.
    ///
    /// Typically, this field is set to 0xFFFF. [Source](https://offwhitesecurity.dev/malware-development/portable-executable-pe/dos-header/).
    #[doc(alias("e_maxalloc"))]
    pub maximum_extra_paragraphs_needed: u16,
    /// In `winnt.h` and `pe.h`, it's `e_ss`.
    ///
    /// It used to specify the initial SS ("stack segment") value. SS value was a paragraph address of the stack segment
    /// relative to the start of the load module. At load time, the value was relocated by adding the address of the
    /// start segment of the program to it, and the resulting value was placed in the SS register before the program is
    /// started. To read more about x86 memory segmentation and SS register, see the
    /// [wikipedia article](https://en.wikipedia.org/wiki/X86_memory_segmentation) on this topic. In DOS, the start segment
    /// boundary of the program was the first segment boundary in memory after
    /// [Program Segment Prefix (PSP)](https://en.wikipedia.org/wiki/Program_Segment_Prefix).
    /// [Source](https://stixproject.github.io/data-model/1.2/WinExecutableFileObj/DOSHeaderType/).
    ///
    /// The Program Segment Prefix (PSP) was a data structure used in DOS (Disk Operating System) environments.
    /// It was located at the beginning of the memory allocated for a running program and it contained various
    /// pieces of information about the program, including command-line arguments, environment variables,
    /// and pointers to various system resources.
    ///
    /// [According to Wikipedia](https://en.wikipedia.org/wiki/Data_segment#Stack), the stack segment contains the call stack,
    /// a LIFO structure, typically located in the higher parts of memory. A "stack pointer" register tracks the top of the
    /// stack; it is adjusted each time a value is "pushed" onto the stack. The set of values pushed for one function call
    /// is termed a "stack frame".
    ///
    /// Typically, this field is set to 0. [Source](https://offwhitesecurity.dev/malware-development/portable-executable-pe/dos-header/).
    #[doc(alias("e_ss"))]
    pub initial_relative_ss: u16,
    /// In `winnt.h` and `pe.h`, it's `e_sp`.
    ///
    /// It used to specify the initial SP ("stack pointer") value. SP value was the absolute value that must have been loaded
    /// into the SP register before the program is given control. Since the actual stack segment was determined by the loader,
    /// and this was merely a value within that segment, it didn't need to be relocated.
    ///
    /// [According to Wikipedia](https://en.wikipedia.org/wiki/Data_segment#Stack), the stack segment contains the call stack,
    /// a LIFO structure, typically located in the higher parts of memory. A "stack pointer" register tracks the top of the
    /// stack; it is adjusted each time a value is "pushed" onto the stack. The set of values pushed for one function call
    /// is termed a "stack frame".
    /// [Source](https://stixproject.github.io/data-model/1.2/WinExecutableFileObj/DOSHeaderType/).
    ///
    /// Typically, this field is set to 0xB8. [Source](https://offwhitesecurity.dev/malware-development/portable-executable-pe/dos-header/).
    // TODO: Clarify what exactly is meany by "this was merely a value within that segment".
    #[doc(alias("e_sp"))]
    pub initial_sp: u16,
    /// e_csum
    #[doc(alias("e_csum"))]
    pub checksum: u16,
    /// e_ip
    #[doc(alias("e_ip"))]
    pub initial_ip: u16,
    /// e_cs
    #[doc(alias("e_cs"))]
    pub initial_relative_cs: u16,
    /// e_lfarlc
    #[doc(alias("e_lfarlc"))]
    pub file_address_of_relocation_table: u16,
    /// e_ovno
    #[doc(alias("e_ovno"))]
    pub overlay_number: u16,
    /// e_res[4]
    #[doc(alias("e_res"))]
    pub reserved: [u16; 4],
    /// e_oemid
    #[doc(alias("e_oemid"))]
    pub oem_id: u16,
    /// e_oeminfo
    #[doc(alias("e_oeminfo"))]
    pub oem_info: u16,
    /// e_res2[10]
    #[doc(alias("e_res2"))]
    pub reserved2: [u16; 10],
    /// e_lfanew: pointer to PE header, always at offset 0x3c
    #[doc(alias("e_lfanew"))]
    pub pe_pointer: u32,
}

#[doc(alias("IMAGE_DOS_SIGNATURE"))]
pub const DOS_MAGIC: u16 = 0x5a4d;
pub const PE_POINTER_OFFSET: u32 = 0x3c;
pub const DOS_STUB_OFFSET: u32 = PE_POINTER_OFFSET + (core::mem::size_of::<u32>() as u32);

impl DosHeader {
    pub fn parse(bytes: &[u8]) -> error::Result<Self> {
        let mut offset = 0;
        let signature = bytes.gread_with(&mut offset, scroll::LE).map_err(|_| {
            error::Error::Malformed(format!("cannot parse DOS signature (offset {:#x})", 0))
        })?;
        if signature != DOS_MAGIC {
            return Err(error::Error::Malformed(format!(
                "DOS header is malformed (signature {:#x})",
                signature
            )));
        }

        let bytes_on_last_page = bytes.gread_with(&mut offset, scroll::LE)?;
        let pages_in_file = bytes.gread_with(&mut offset, scroll::LE)?;
        let relocations = bytes.gread_with(&mut offset, scroll::LE)?;
        let size_of_header_in_paragraphs = bytes.gread_with(&mut offset, scroll::LE)?;
        let minimum_extra_paragraphs_needed = bytes.gread_with(&mut offset, scroll::LE)?;
        let maximum_extra_paragraphs_needed = bytes.gread_with(&mut offset, scroll::LE)?;
        let initial_relative_ss = bytes.gread_with(&mut offset, scroll::LE)?;
        let initial_sp = bytes.gread_with(&mut offset, scroll::LE)?;
        let checksum = bytes.gread_with(&mut offset, scroll::LE)?;
        let initial_ip = bytes.gread_with(&mut offset, scroll::LE)?;
        let initial_relative_cs = bytes.gread_with(&mut offset, scroll::LE)?;
        let file_address_of_relocation_table = bytes.gread_with(&mut offset, scroll::LE)?;
        let overlay_number = bytes.gread_with(&mut offset, scroll::LE)?;
        let reserved = [0x0; 4];
        offset += core::mem::size_of_val(&reserved);
        let oem_id = bytes.gread_with(&mut offset, scroll::LE)?;
        let oem_info = bytes.gread_with(&mut offset, scroll::LE)?;
        let reserved2 = [0x0; 10];
        offset += core::mem::size_of_val(&reserved2);

        debug_assert!(
            offset == PE_POINTER_OFFSET as usize,
            "expected offset ({:#x}) after reading DOS header to be at 0x3C",
            offset
        );

        let pe_pointer = bytes
            .pread_with(PE_POINTER_OFFSET as usize, scroll::LE)
            .map_err(|_| {
                error::Error::Malformed(format!(
                    "cannot parse PE header pointer (offset {:#x})",
                    PE_POINTER_OFFSET
                ))
            })?;

        let pe_signature: u32 =
            bytes
                .pread_with(pe_pointer as usize, scroll::LE)
                .map_err(|_| {
                    error::Error::Malformed(format!(
                        "cannot parse PE header signature (offset {:#x})",
                        pe_pointer
                    ))
                })?;
        if pe_signature != PE_MAGIC {
            return Err(error::Error::Malformed(format!(
                "PE header is malformed (signature {:#x})",
                pe_signature
            )));
        }

        Ok(DosHeader {
            signature,
            bytes_on_last_page,
            pages_in_file,
            relocations,
            size_of_header_in_paragraphs,
            minimum_extra_paragraphs_needed,
            maximum_extra_paragraphs_needed,
            initial_relative_ss,
            initial_sp,
            checksum,
            initial_ip,
            initial_relative_cs,
            file_address_of_relocation_table,
            overlay_number,
            reserved,
            oem_id,
            oem_info,
            reserved2,
            pe_pointer,
        })
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Pread, Pwrite)]
/// The DOS stub program which should be executed in DOS mode
pub struct DosStub(pub [u8; 0x40]);
impl Default for DosStub {
    fn default() -> Self {
        // "This program cannot be run in DOS mode" error program
        Self([
            0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
            0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63,
            0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69,
            0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
            0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
    }
}

/// COFF Header
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct CoffHeader {
    /// The machine type
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbol_table: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

pub const SIZEOF_COFF_HEADER: usize = 20;
/// PE\0\0, little endian
pub const PE_MAGIC: u32 = 0x0000_4550;
pub const SIZEOF_PE_MAGIC: usize = 4;
/// The contents of this field are assumed to be applicable to any machine type
pub const COFF_MACHINE_UNKNOWN: u16 = 0x0;
/// Matsushita AM33
pub const COFF_MACHINE_AM33: u16 = 0x1d3;
/// x64
pub const COFF_MACHINE_X86_64: u16 = 0x8664;
/// ARM little endian
pub const COFF_MACHINE_ARM: u16 = 0x1c0;
/// ARM64 little endian
pub const COFF_MACHINE_ARM64: u16 = 0xaa64;
/// ARM Thumb-2 little endian
pub const COFF_MACHINE_ARMNT: u16 = 0x1c4;
/// EFI byte code
pub const COFF_MACHINE_EBC: u16 = 0xebc;
/// Intel 386 or later processors and compatible processors
pub const COFF_MACHINE_X86: u16 = 0x14c;
/// Intel Itanium processor family
pub const COFF_MACHINE_IA64: u16 = 0x200;
/// Mitsubishi M32R little endian
pub const COFF_MACHINE_M32R: u16 = 0x9041;
/// MIPS16
pub const COFF_MACHINE_MIPS16: u16 = 0x266;
/// MIPS with FPU
pub const COFF_MACHINE_MIPSFPU: u16 = 0x366;
/// MIPS16 with FPU
pub const COFF_MACHINE_MIPSFPU16: u16 = 0x466;
/// Power PC little endian
pub const COFF_MACHINE_POWERPC: u16 = 0x1f0;
/// Power PC with floating point support
pub const COFF_MACHINE_POWERPCFP: u16 = 0x1f1;
/// MIPS little endian
pub const COFF_MACHINE_R4000: u16 = 0x166;
/// RISC-V 32-bit address space
pub const COFF_MACHINE_RISCV32: u16 = 0x5032;
/// RISC-V 64-bit address space
pub const COFF_MACHINE_RISCV64: u16 = 0x5064;
/// RISC-V 128-bit address space
pub const COFF_MACHINE_RISCV128: u16 = 0x5128;
/// Hitachi SH3
pub const COFF_MACHINE_SH3: u16 = 0x1a2;
/// Hitachi SH3 DSP
pub const COFF_MACHINE_SH3DSP: u16 = 0x1a3;
/// Hitachi SH4
pub const COFF_MACHINE_SH4: u16 = 0x1a6;
/// Hitachi SH5
pub const COFF_MACHINE_SH5: u16 = 0x1a8;
/// Thumb
pub const COFF_MACHINE_THUMB: u16 = 0x1c2;
/// MIPS little-endian WCE v2
pub const COFF_MACHINE_WCEMIPSV2: u16 = 0x169;

impl CoffHeader {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        Ok(bytes.gread_with(offset, scroll::LE)?)
    }

    /// Parse the COFF section headers.
    ///
    /// For COFF, these immediately follow the COFF header. For PE, these immediately follow the
    /// optional header.
    pub fn sections(
        &self,
        bytes: &[u8],
        offset: &mut usize,
    ) -> error::Result<Vec<section_table::SectionTable>> {
        let nsections = self.number_of_sections as usize;

        // a section table is at least 40 bytes
        if nsections > bytes.len() / 40 {
            return Err(error::Error::BufferTooShort(nsections, "sections"));
        }

        let mut sections = Vec::with_capacity(nsections);
        // Note that if we are handling a BigCoff, the size of the symbol will be different!
        let string_table_offset = self.pointer_to_symbol_table as usize
            + symbol::SymbolTable::size(self.number_of_symbol_table as usize);
        for i in 0..nsections {
            let section =
                section_table::SectionTable::parse(bytes, offset, string_table_offset as usize)?;
            debug!("({}) {:#?}", i, section);
            sections.push(section);
        }
        Ok(sections)
    }

    /// Return the COFF symbol table.
    pub fn symbols<'a>(&self, bytes: &'a [u8]) -> error::Result<Option<symbol::SymbolTable<'a>>> {
        let offset = self.pointer_to_symbol_table as usize;
        let number = self.number_of_symbol_table as usize;
        if offset == 0 {
            Ok(None)
        } else {
            symbol::SymbolTable::parse(bytes, offset, number).map(Some)
        }
    }

    /// Return the COFF string table.
    pub fn strings<'a>(&self, bytes: &'a [u8]) -> error::Result<Option<strtab::Strtab<'a>>> {
        // > The file offset of the COFF symbol table, or zero if no COFF symbol table is present.
        // > This value should be zero for an image because COFF debugging information is deprecated.
        if self.pointer_to_symbol_table == 0 {
            return Ok(None);
        }

        let mut offset = self.pointer_to_symbol_table as usize
            + symbol::SymbolTable::size(self.number_of_symbol_table as usize);

        let length_field_size = core::mem::size_of::<u32>();
        let length = bytes.pread_with::<u32>(offset, scroll::LE)? as usize - length_field_size;

        // The offset needs to be advanced in order to read the strings.
        offset += length_field_size;

        Ok(Some(strtab::Strtab::parse(bytes, offset, length, 0)?))
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct Header {
    pub dos_header: DosHeader,
    /// DOS program for legacy loaders
    pub dos_stub: DosStub,
    /// PE Magic: PE\0\0, little endian
    pub signature: u32,
    pub coff_header: CoffHeader,
    pub optional_header: Option<optional_header::OptionalHeader>,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> error::Result<Self> {
        let dos_header = DosHeader::parse(&bytes)?;
        let dos_stub = bytes.pread(DOS_STUB_OFFSET as usize).map_err(|_| {
            error::Error::Malformed(format!(
                "cannot parse DOS stub (offset {:#x})",
                DOS_STUB_OFFSET
            ))
        })?;
        let mut offset = dos_header.pe_pointer as usize;
        let signature = bytes.gread_with(&mut offset, scroll::LE).map_err(|_| {
            error::Error::Malformed(format!("cannot parse PE signature (offset {:#x})", offset))
        })?;
        let coff_header = CoffHeader::parse(&bytes, &mut offset)?;
        let optional_header = if coff_header.size_of_optional_header > 0 {
            Some(bytes.pread::<optional_header::OptionalHeader>(offset)?)
        } else {
            None
        };
        Ok(Header {
            dos_header,
            dos_stub,
            signature,
            coff_header,
            optional_header,
        })
    }
}

impl ctx::TryIntoCtx<scroll::Endian> for Header {
    type Error = error::Error;

    fn try_into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) -> Result<usize, Self::Error> {
        let offset = &mut 0;
        bytes.gwrite_with(self.dos_header, offset, ctx)?;
        bytes.gwrite_with(self.dos_stub, offset, ctx)?;
        bytes.gwrite_with(self.signature, offset, scroll::LE)?;
        bytes.gwrite_with(self.coff_header, offset, ctx)?;
        if let Some(opt_header) = self.optional_header {
            bytes.gwrite_with(opt_header, offset, ctx)?;
        }
        Ok(*offset)
    }
}

/// Convert machine to str representation
pub fn machine_to_str(machine: u16) -> &'static str {
    match machine {
        COFF_MACHINE_UNKNOWN => "UNKNOWN",
        COFF_MACHINE_AM33 => "AM33",
        COFF_MACHINE_X86_64 => "X86_64",
        COFF_MACHINE_ARM => "ARM",
        COFF_MACHINE_ARM64 => "ARM64",
        COFF_MACHINE_ARMNT => "ARM_NT",
        COFF_MACHINE_EBC => "EBC",
        COFF_MACHINE_X86 => "X86",
        COFF_MACHINE_IA64 => "IA64",
        COFF_MACHINE_M32R => "M32R",
        COFF_MACHINE_MIPS16 => "MIPS_16",
        COFF_MACHINE_MIPSFPU => "MIPS_FPU",
        COFF_MACHINE_MIPSFPU16 => "MIPS_FPU_16",
        COFF_MACHINE_POWERPC => "POWERPC",
        COFF_MACHINE_POWERPCFP => "POWERCFP",
        COFF_MACHINE_R4000 => "R4000",
        COFF_MACHINE_RISCV32 => "RISC-V_32",
        COFF_MACHINE_RISCV64 => "RISC-V_64",
        COFF_MACHINE_RISCV128 => "RISC-V_128",
        COFF_MACHINE_SH3 => "SH3",
        COFF_MACHINE_SH3DSP => "SH3DSP",
        COFF_MACHINE_SH4 => "SH4",
        COFF_MACHINE_SH5 => "SH5",
        COFF_MACHINE_THUMB => "THUMB",
        COFF_MACHINE_WCEMIPSV2 => "WCE_MIPS_V2",
        _ => "COFF_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::{machine_to_str, Header, COFF_MACHINE_X86, DOS_MAGIC, PE_MAGIC};

    const CRSS_HEADER: [u8; 688] = [
        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
        0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xd0, 0x00, 0x00, 0x00, 0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01,
        0x4c, 0xcd, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d,
        0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20,
        0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x4a, 0xc3, 0xeb, 0xee, 0x2b, 0xad,
        0xb8, 0xee, 0x2b, 0xad, 0xb8, 0xee, 0x2b, 0xad, 0xb8, 0xee, 0x2b, 0xac, 0xb8, 0xfe, 0x2b,
        0xad, 0xb8, 0x33, 0xd4, 0x66, 0xb8, 0xeb, 0x2b, 0xad, 0xb8, 0x33, 0xd4, 0x63, 0xb8, 0xea,
        0x2b, 0xad, 0xb8, 0x33, 0xd4, 0x7a, 0xb8, 0xed, 0x2b, 0xad, 0xb8, 0x33, 0xd4, 0x64, 0xb8,
        0xef, 0x2b, 0xad, 0xb8, 0x33, 0xd4, 0x61, 0xb8, 0xef, 0x2b, 0xad, 0xb8, 0x52, 0x69, 0x63,
        0x68, 0xee, 0x2b, 0xad, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45,
        0x00, 0x00, 0x4c, 0x01, 0x05, 0x00, 0xd9, 0x8f, 0x15, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xe0, 0x00, 0x02, 0x01, 0x0b, 0x01, 0x0b, 0x00, 0x00, 0x08, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x06, 0x00, 0x03, 0x00, 0x06, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0xe4, 0xab, 0x00, 0x00,
        0x01, 0x00, 0x40, 0x05, 0x00, 0x00, 0x04, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x30, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x1a, 0x00, 0x00, 0xb8, 0x22, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x38, 0x00, 0x00,
        0x00, 0x10, 0x10, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x68, 0x10, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x24,
        0x06, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
        0x60, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x3c, 0x03, 0x00, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xc0, 0x2e, 0x69, 0x64, 0x61,
        0x74, 0x61, 0x00, 0x00, 0xf8, 0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2e, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
        0x42, 0x2e, 0x72, 0x65, 0x6c, 0x6f, 0x63, 0x00, 0x00, 0x86, 0x01, 0x00, 0x00, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn crss_header() {
        let header = Header::parse(&&CRSS_HEADER[..]).unwrap();
        assert!(header.dos_header.signature == DOS_MAGIC);
        assert!(header.signature == PE_MAGIC);
        assert!(header.coff_header.machine == COFF_MACHINE_X86);
        assert!(machine_to_str(header.coff_header.machine) == "X86");
        println!("header: {:?}", &header);
    }
}
