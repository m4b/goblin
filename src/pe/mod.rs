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
pub mod import;
mod utils;

use error::*;

#[derive(Debug)]
pub struct PE {
    pub header: header::Header,
    pub sections: Vec<section_table::SectionTable>,
    pub size: usize,
    pub name: Option<String>,
    pub is_lib: bool,
    pub entry: usize,
    pub image_base: usize,
    pub export_data: Option<export::ExportData>,
    pub import_data: Option<import::ImportData>,
    pub exports: Vec<export::Export>,
    pub imports: Vec<import::Import>,
    pub libraries: Vec<String>,
}

impl PE {
    pub fn parse<B: scroll::Gread + scroll::Gread<scroll::Error, scroll::ctx::StrCtx>>(bytes: &B) -> Result<Self> {
        let header = header::Header::parse(bytes)?;
        let mut offset = &mut (header.dos_header.pe_pointer as usize + header::SIZEOF_COFF_HEADER + header.coff_header.size_of_optional_header as usize);
        let nsections = header.coff_header.number_of_sections as usize;
        let mut sections = Vec::with_capacity(nsections);
        for _ in 0..nsections {
            sections.push(section_table::SectionTable::parse(bytes, offset)?);
        }
        let is_lib = characteristic::is_dll(header.coff_header.characteristics);
        let mut entry = 0;
        let mut image_base = 0;
        let mut exports = vec![];
        let mut export_data = None;
        let mut name = None;
        let mut imports = vec![];
        let mut import_data = None;
        let mut libraries = vec![];
        if let Some(optional_header) = header.optional_header {
            entry = optional_header.standard_fields.address_of_entry_point as usize;
            image_base = optional_header.windows_fields.image_base as usize;
            if let &Some(export_table) = optional_header.data_directories.get_export_table() {
                let ed = export::ExportData::parse(bytes, &export_table, &sections)?;
                exports = export::Export::parse(bytes, &ed, &sections)?;
                name = Some(ed.name.to_owned());
                export_data = Some(ed);
            }
            if let &Some(import_table) = optional_header.data_directories.get_import_table() {
                let id = import::ImportData::parse(bytes, &import_table, &sections)?;
                imports = import::Import::parse(bytes, &id, &sections)?;
                libraries = id.import_data.iter().map( | data | { data.name.to_owned() }).collect::<Vec<String>>();
                libraries.sort();
                libraries.dedup();
                import_data = Some(id);
            }
        }
        Ok( PE {
            header: header,
            sections: sections,
            size: 0,
            name: name,
            is_lib: is_lib,
            entry: entry,
            image_base: image_base,
            export_data: export_data,
            import_data: import_data,
            exports: exports,
            imports: imports,
            libraries: libraries,
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
