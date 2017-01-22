use scroll;

use std::io::Read;
use scroll::Buffer;

pub use super::error;
pub mod header;
pub mod optional_header;
pub mod characteristic;
pub mod section_table;
pub mod data_directories;
pub mod export;
mod utils;

use error::*;

#[derive(Debug)]
pub struct PE {
    pub header: header::Header,
    pub sections: Vec<section_table::SectionTable>,
    pub size: usize,
    pub libraries: Vec<String>,
    pub name: Option<String>,
    pub is_lib: bool,
    pub entry: usize,
    pub image_base: usize,
    pub exports: Vec<export::Export>,
    pub export_data: Option<export::ExportData>,
    // import_data: Import.import_data option,
    // imports: Import.t,
}

impl PE {
    pub fn parse<B: scroll::Gread>(bytes: &B) -> Result<Self> {
        let header = header::Header::parse(bytes)?;
        let mut offset = &mut (header.dos_header.pe_pointer as usize + header::SIZEOF_COFF_HEADER + header.coff_header.size_of_optional_header as usize);
        let nsections = header.coff_header.number_of_sections as usize;
        let mut sections = Vec::with_capacity(nsections);
        for _ in 0..nsections {
            sections.push(section_table::SectionTable::parse(bytes, offset)?);
        }
        let is_lib = characteristic::is_dll(header.coff_header.characteristics);
        let libraries = vec![];
        let mut entry = 0;
        let mut image_base = 0;
        let mut exports = vec![];
        let mut export_data = None;
        let mut name = None;
        if let Some(optional_header) = header.optional_header {
            entry = optional_header.standard_fields.address_of_entry_point as usize;
            image_base = optional_header.windows_fields.image_base as usize;
            // if let &Some(export_table) = optional_header.data_directories.get_export_table() {
            //     export_data = Some(export::ExportData::parse(bytes, &export_table, &sections)?);
            // }
        }
        Ok( PE {
            header: header,
            sections: sections,
            size: 0,
            libraries: libraries,
            name: name,
            is_lib: is_lib,
            entry: entry,
            image_base: image_base,
            exports: exports,
            export_data: export_data,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        PE::parse(&bytes)
    }

    pub fn try_from<R: Read>(fd: &mut R) -> Result<Self> {
        let buffer = Buffer::try_from(fd)?;
        PE::parse(&buffer)
    }
}
