use alloc::vec::Vec;
use core::mem::size_of;

/// Meta writer structures for PE
/// PE is a complicated format that requires meta knowledge about all its fields
/// and reorganization at write time as we cannot predict all fields based on local information.
/// This file contains global structure which possess the global information to make up
/// for the complexity of PE.
/// Heavily inspired of how LLVM objcopy works for COFF.
use log::debug;
use log::trace;
use scroll::Pread;
use scroll::Pwrite;

use crate::pe::certificate_table::enumerate_certificates;
use crate::pe::data_directories::SIZEOF_DATA_DIRECTORY;
use crate::pe::header::SIZEOF_COFF_HEADER;
use crate::pe::optional_header::StandardFields32;
use crate::pe::optional_header::StandardFields64;
use crate::pe::optional_header::WindowsFields32;
use crate::pe::optional_header::WindowsFields64;

use crate::pe::utils::align_to;

use super::data_directories::DataDirectory;
use super::data_directories::DataDirectoryType;
use super::debug::ImageDebugDirectory;
use super::error;
use super::header::DosHeader;
use super::header::DosStub;
use super::optional_header::OptionalHeader;
use super::section_table::Section;
use super::section_table::SectionTable;
use super::section_table::IMAGE_SCN_CNT_INITIALIZED_DATA;
use super::section_table::IMAGE_SCN_MEM_EXECUTE;
use super::section_table::IMAGE_SCN_MEM_READ;
use super::section_table::IMAGE_SCN_MEM_WRITE;
use super::utils::is_in_range;
use super::utils::rva2offset;
use super::PE;

// The maximum number of sections that a COFF object can have (inclusive)
// which is a strict limit for PE, taken from LLVM.
const MAX_NUMBER_OF_SECTIONS_PE: usize = 65279;

pub struct PEWriter<'a, 'b> {
    pe: PE<'a>,
    file_size: u32,
    file_alignment: u32,
    section_alignment: u32,
    size_of_initialized_data: u64,
    pending_sections: Vec<Section<'b>>,
    ready_sections: Vec<Section<'b>>,
}

impl<'a, 'b> PEWriter<'a, 'b> {
    /// Consume the PE and store on-the-side information to rewrite
    /// this PE with new information, e.g. new sections.
    /// Some data can be manipulated beforehand and will be correctly rewritten
    /// but this is very driven by implementation details.
    /// It is guaranteed to work for new sections and removed sections, not for much more.
    pub fn new(pe: PE<'a>) -> error::Result<Self> {
        let header = pe.header.optional_header.ok_or(error::Error::Malformed(
            "Missing optional header, write is not supported in this usecase".into(),
        ))?;
        Ok(Self {
            pe,
            file_size: 0,
            file_alignment: header.windows_fields.file_alignment,
            section_alignment: header.windows_fields.section_alignment,
            size_of_initialized_data: 0,
            pending_sections: Vec::new(),
            ready_sections: Vec::new(),
        })
    }

    /// Enqueue a pending section to be laid out at write time.
    /// Fields that are impossible to predict can be left out
    /// and will be filled automatically.
    pub fn insert_section(&mut self, mut section: Section<'b>) -> error::Result<()> {
        // VA is needed only if characteristics is
        // execute | read | write.
        let need_virtual_address = (section.table.characteristics
            & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE))
            != 0;

        if let Some(contents) = &section.contents {
            debug_assert!(need_virtual_address, "contents present without any need for a virtual address; missing flag on characteristics?");
            section.table.virtual_size = contents.len().try_into()?;
            let mut sections = self.pe.sections.clone();
            sections.sort_by_key(|sect| sect.virtual_address);
            let last_section_offset = sections
                .iter()
                .chain(self.pending_sections.iter().map(|sect| &sect.table))
                .last()
                .map(|last_section| last_section.virtual_address + last_section.virtual_size)
                .ok_or(0u32)
                .unwrap();

            section.table.virtual_address = align_to(last_section_offset, self.section_alignment);
            debug!(
                "[section {:?}] virtual address assigned: {}",
                section.table.name, section.table.virtual_address
            );
        }

        self.pending_sections.push(section);
        Ok(())
    }

    /// This will compute all the missing fields for a pending section
    /// and put it inside the "ready" sections array for the writer
    /// It relies on the global internal `self.file_size` and
    /// `self.size_of_initialized_data` state to adjust the "on-disk" pointers.
    fn layout_sections(&mut self) -> error::Result<()> {
        fn layout_section(
            file_size: &mut u32,
            size_of_initialized_data: &mut u64,
            header: &mut SectionTable,
            data_length: usize,
            n_relocations: usize,
            file_alignment: u32,
        ) -> error::Result<()> {
            header.size_of_raw_data = align_to(data_length as u32, file_alignment);
            if header.size_of_raw_data > 0 {
                header.pointer_to_raw_data = *file_size;
            }

            if n_relocations > 0 {
                return Err(error::Error::Malformed(
                    "COFF are unsupported; PE should not have relocations!".into(),
                ));
            }

            *file_size += header.size_of_raw_data;
            *file_size = align_to(*file_size, file_alignment);

            if header.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA
                == IMAGE_SCN_CNT_INITIALIZED_DATA
            {
                *size_of_initialized_data += header.size_of_raw_data as u64;
            }

            Ok(())
        }
        for section in &mut self.pe.sections {
            layout_section(
                &mut self.file_size,
                &mut self.size_of_initialized_data,
                section,
                section.size_of_raw_data as usize,
                section.number_of_relocations.into(),
                self.file_alignment,
            )?;
        }
        while !self.pending_sections.is_empty() {
            let mut section = self.pending_sections.pop().unwrap();

            layout_section(
                &mut self.file_size,
                &mut self.size_of_initialized_data,
                &mut section.table,
                section.contents.as_ref().map(|c| c.len()).unwrap_or(0),
                section.relocations.len(),
                self.file_alignment,
            )?;

            self.ready_sections.push(section);
        }

        // Sections were added in LIFO style.
        // This means that the last element here is the first pending section.
        // i.e. section with the lowest virtual address.
        // To maintain the sorting invariant, we just need to reverse the list.
        self.ready_sections.reverse();

        Ok(())
    }

    fn layout_certificates(&mut self) -> error::Result<u32> {
        let mut total_length = 0;
        for certificate in &self.pe.certificates {
            self.file_size += certificate.length;
            total_length += certificate.length;
        }
        Ok(total_length)
    }

    fn layout_data_directories_contents(
        &mut self,
        opt_header: &mut OptionalHeader,
    ) -> error::Result<()> {
        for (index, dir) in opt_header
            .data_directories
            .data_directories
            .iter_mut()
            .enumerate()
        {
            trace!("{}: {:?}", index, dir);
            let dd_type: DataDirectoryType = index.try_into()?;
            // skip certificate table, we don't use size here.
            // skip the debug table, it must be ordered *after* the certificate table
            // as per:
            // > Another exception is that attribute certificate and debug information must be placed
            // > at the very end of an image file, with the attribute certificate table immediately
            // > preceding the debug section, because the loader does not map these into memory. The
            // > rule about attribute certificate and debug information does not apply to object
            // > files, however.
            // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#other-contents-of-the-file
            if dd_type == DataDirectoryType::CertificateTable
                || dd_type == DataDirectoryType::DebugTable
            {
                continue;
            }

            if let Some((offset, dd)) = dir {
                *offset = self.file_size as usize;
                self.file_size += dd.size;
            }
        }
        // 4 := certificate data directory
        // it is special because it virtual size does not reflect the full size
        // of attribute certificates available.
        // virtual size is only the size of a single bundle of certificate.
        if let Some((_cert_offset, cert_table)) =
            opt_header.data_directories.data_directories[4].as_mut()
        {
            cert_table.virtual_address = self.file_size;
            cert_table.size = self.layout_certificates()?;
        }
        // 6 := debug table
        // it is special because if it exist, it must be *after* the certificate table.
        // this is incorrect, the data directory offset must point at some section offset.
        if let Some((debug_offset, debug_table)) =
            opt_header.data_directories.data_directories[6].as_mut()
        {
            *debug_offset = self.file_size as usize;
            self.file_size += debug_table.size;
        }
        Ok(())
    }

    fn finalize(&mut self) -> error::Result<()> {
        // XXX(RaitoBezarius): some steps of finalization are "commented out"
        // They would be necessary if you are planning to support those codepaths for COFF Object
        // File write support, I do not want to support them, I will stop at supporting *PE
        // executables*.
        // 1. finalize symbol table
        // FIXME: COFF are unsupported ; self.finalize_symbol_table()?;
        // 2. finalize relocation targets
        // FIXME: COFF are unsupported ; self.finalize_relocation_targets()?;
        // 3. finalize symbol contents
        // FIXME: COFF are unsupported ; self.finalize_symbol_contents()?;
        // 4. compute the address of the new exe header
        let mut size_of_headers: u32 = 0;
        let pe_header_size: u32 = {
            if self.pe.is_64 {
                size_of::<StandardFields64>() as u32 + size_of::<WindowsFields64>() as u32
            } else {
                size_of::<StandardFields32>() as u32 + size_of::<WindowsFields32>() as u32
            }
        };
        self.pe.header.dos_header.pe_pointer =
            (size_of::<DosHeader>() + size_of::<DosStub>()) as u32;
        debug_assert!(
            self.pe.header.dos_header.pe_pointer >= 0x40,
            "PE pointer < 0x40, this is not expected."
        );
        // 5. compute the initial pe header size
        let mut opt_header = self
            .pe
            .header
            .optional_header
            .ok_or(error::Error::Malformed(
                "Missing optional header for a PE".into(),
            ))?;
        // Count data directories in the PE.
        opt_header.windows_fields.number_of_rva_and_sizes = 16; // TODO(raito): opt_header.data_directories.dirs().count() as u32; is better but requires the write operation for DD to skip none dds.
        size_of_headers += pe_header_size
            + (SIZEOF_DATA_DIRECTORY as u32) * opt_header.windows_fields.number_of_rva_and_sizes;
        // 6. compute the number of sections
        self.pe.header.coff_header.number_of_sections =
            (self.pe.sections.len() + self.pending_sections.len()) as u16;
        size_of_headers += SIZEOF_COFF_HEADER as u32;
        size_of_headers += (size_of::<SectionTable>() as u32)
            * (self.pe.header.coff_header.number_of_sections as u32);
        size_of_headers = align_to(size_of_headers, self.file_alignment);
        // 7. compute the optional header size
        self.pe.header.coff_header.size_of_optional_header = u16::try_from(pe_header_size)?
            + (SIZEOF_DATA_DIRECTORY as u16)
                * u16::try_from(opt_header.windows_fields.number_of_rva_and_sizes)?;
        // 8. set file size
        self.file_size = size_of_headers;
        self.size_of_initialized_data = 0;
        // 9. layout all sections and data directories contents
        self.layout_sections()?;
        self.layout_data_directories_contents(&mut opt_header)?;
        // 10. adjust PE specific headers w.r.t to sizes
        opt_header.windows_fields.size_of_headers = size_of_headers;
        opt_header.standard_fields.size_of_initialized_data = self.size_of_initialized_data;

        if let Some(last_section) = self
            .pe
            .sections
            .iter()
            .chain(self.ready_sections.iter().map(|s| &s.table))
            .last()
        {
            opt_header.windows_fields.size_of_image = align_to(
                last_section.virtual_address + last_section.virtual_size,
                self.section_alignment,
            );
        }

        // Clear the checksum and do not compute it.
        opt_header.windows_fields.check_sum = 0;

        // 11. FIXME: COFF are unsupported ; finalize string tables

        self.pe.header.optional_header = Some(opt_header);
        self.file_size = align_to(self.file_size, self.file_alignment);
        Ok(())
    }

    fn write_headers(&mut self, buf: &mut Vec<u8>) -> error::Result<usize> {
        let offset = &mut 0;
        // 1. write the header
        debug!("writing this header: {:#?}", self.pe.header);
        buf.gwrite(self.pe.header, offset)?;
        // 2. write the section tables
        for section in self
            .pe
            .sections
            .iter()
            .chain(self.ready_sections.iter().map(|s| &s.table))
        {
            debug!(
                "writing section table {} at {}",
                section.name().unwrap_or("unknown name"),
                offset
            );
            buf.gwrite(section, offset)?;
        }

        Ok(*offset)
    }

    fn write_sections(&mut self, buf: &mut Vec<u8>) -> error::Result<usize> {
        // For each section, seek at the pointer to raw data, write the contents.
        // For executable sections, pad the remainder of the raw data size
        // with 0xCC, because it's useful on x86 (debugger breakpoint).
        let mut written = 0;
        let ready_sections = core::mem::take(&mut self.ready_sections);
        for section in self
            .pe
            .sections
            .iter()
            .cloned()
            .map(|s| s.into_section(&self.pe.bytes).unwrap())
            .chain(ready_sections.into_iter())
        {
            let offset = section.table.pointer_to_raw_data as usize;
            if let Some(contents) = &section.contents {
                written += buf.pwrite(contents.as_ref(), offset)?;
                debug!(
                    "wrote {} (true size: {}) contents at {}",
                    contents.len(),
                    section.table.size_of_raw_data,
                    offset
                );
                if section.table.size_of_raw_data as usize > contents.len() {
                    written += buf.pwrite(
                        &vec![0xCC; (section.table.size_of_raw_data as usize) - contents.len()][..],
                        offset + contents.len(),
                    )?;
                }
            }
        }
        // FIXME: COFF are unsupported but you would need to write the relocations here and
        // distinguish based on the size of the COFF object.
        Ok(written)
    }

    fn patch_debug_directory(
        &mut self,
        debug_directory: &DataDirectory,
        w: &mut Vec<u8>,
    ) -> error::Result<usize> {
        if debug_directory.size == 0 {
            return Ok(0);
        }

        for section in &self.pe.sections {
            let section_end = section.virtual_address + section.virtual_size;

            if is_in_range(
                debug_directory.virtual_address as usize,
                section.virtual_address as usize,
                section_end as usize,
            ) {
                if debug_directory.virtual_address + debug_directory.size > section_end {
                    return Err(error::Error::Malformed(
                        "debug directory extends past end of section".into(),
                    ));
                }

                // We compute the relative difference inside the section
                let offset = debug_directory.virtual_address - section.virtual_address;
                // We compute the pointer to raw data for the debug dir
                // based on the on-disk offset section + relative diff
                // as mapping is linear.
                let mut target_offset = (section.pointer_to_raw_data + offset) as usize;
                let end = target_offset + debug_directory.size as usize;
                // Read until target_offset + debug_directory.size
                while target_offset < end {
                    let mut debug_data: ImageDebugDirectory =
                        w.gread::<ImageDebugDirectory>(&mut target_offset)?;
                    if debug_data.pointer_to_raw_data != 0 {
                        debug_data.pointer_to_raw_data =
                            rva2offset(debug_data.address_of_raw_data as usize, section)
                                .try_into()?;
                        // We rewrite the previous pointer inside the memory buffer
                        // Right now, we are sitting potentially onto the next ImageDebugDirectory
                        // or the end.
                        // It is therefore enough to start from target_offset, go back to previous
                        // element and go to the relevant field immediately.

                        w.pwrite(
                            debug_data.pointer_to_raw_data,
                            target_offset + 0x18 - size_of::<ImageDebugDirectory>(),
                        )?;
                    }
                }
            }
        }

        Ok(0)
    }

    pub fn write_into(&mut self) -> error::Result<Vec<u8>> {
        let total_sections = self.pending_sections.len() + self.pe.sections.len();
        let is_too_large = total_sections >= MAX_NUMBER_OF_SECTIONS_PE;

        if is_too_large {
            return Err(error::Error::Malformed(
                format!("Trying to write {total_sections} sections, the limit is {MAX_NUMBER_OF_SECTIONS_PE} for a PE binary")
            ));
        }

        let mut written = 0;

        self.finalize()?;
        debug!("finalized the new PE binary at {} bytes", self.file_size);
        let mut buffer = vec![0; self.file_size as usize];

        written += self.write_headers(&mut buffer)?;
        debug!("wrote headers");
        written += self.write_sections(&mut buffer)?;
        debug!("wrote sections");
        // FIXME: COFF are unsupported ; written += self.write_symbol_string_tables(&mut buffer)?;
        if let Some((_, debug_dir)) = &self
            .pe
            .header
            .optional_header
            .and_then(|opt_header| opt_header.data_directories.data_directories[6])
        {
            self.patch_debug_directory(debug_dir, &mut buffer)?;
            debug!("patched debug directory");
        }
        written += self
            .pe
            .write_data_directories(
                &mut buffer[..],
                &self.pe.header.optional_header.unwrap().data_directories,
                scroll::LE,
            )?
            .0;
        debug!("wrote data directories contents");

        // Specification says that:
        // if cert table and debug table exist, they must be at the very end in this order
        // if cert table exist, it should be the last element
        // if debug table exist, it should be the last element
        // This is important because they are not mapped in memory.
        // TODO: reintroduce it.

        // We cannot guarantee that written == self.file_size
        // as PE cannot be perfectly efficient vs. how we do write them.
        // For example, if you have 1 data directory and it is the last one,
        // you will have to say that you have all data directories and will only write one data
        // directory header, but your file size will reflect the potential size of all data
        // directories contents.
        // Of course, it is possible to improve many moving parts and make it quite efficient.
        // PRs are welcome as correctness is already a good enough goal with PEs.
        debug_assert!(
            written <= self.file_size as usize,
            "incorrect amount of bytes written, expected at most: {}, wrote: {}",
            self.file_size,
            written
        );
        Ok(buffer)
    }
}
