//! A PE32 and PE32+ parser
//!

pub mod header;
pub mod optional_header;
pub mod characteristic;
pub mod section_table;
pub mod data_directories;
pub mod export;
pub mod import;
mod utils;

use error;
use container;

#[derive(Debug)]
/// An analyzed PE32/PE32+ binary
pub struct PE<'a> {
    /// The PE header
    pub header: header::Header,
    /// A list of the sections in this PE binary
    pub sections: Vec<section_table::SectionTable>,
    /// The size of the binary
    pub size: usize,
    /// The name of this `dll`, if it has one
    pub name: Option<&'a str>,
    /// Whether this is a `dll` or not
    pub is_lib: bool,
    /// Whether the binary is 64-bit (PE32+)
    pub is_64: bool,
    /// the entry point of the binary
    pub entry: usize,
    /// The binary's RVA, or image base - useful for computing virtual addreses
    pub image_base: usize,
    /// Data about any exported symbols in this binary (e.g., if it's a `dll`)
    pub export_data: Option<export::ExportData<'a>>,
    /// Data for any imported symbols, and from which `dll`, etc., in this binary
    pub import_data: Option<import::ImportData<'a>>,
    /// The list of exported symbols in this binary, contains synthetic information for easier analysis
    pub exports: Vec<export::Export<'a>>,
    /// The list symbols imported by this binary from other `dll`s
    pub imports: Vec<import::Import<'a>>,
    /// The list of libraries which this binary imports symbols from
    pub libraries: Vec<&'a str>,
}

impl<'a> PE<'a> {
    /// Reads a PE binary from the underlying `bytes`
    pub fn parse(bytes: &'a [u8]) -> error::Result<Self> {
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
        let mut is_64 = false;
        if let Some(optional_header) = header.optional_header {
            entry = optional_header.standard_fields.address_of_entry_point as usize;
            image_base = optional_header.windows_fields.image_base as usize;
            is_64 = optional_header.container()? == container::Container::Big;
            if let &Some(export_table) = optional_header.data_directories.get_export_table() {
                let ed = export::ExportData::parse(bytes, &export_table, &sections)?;
                exports = export::Export::parse(bytes, &ed, &sections)?;
                name = Some(ed.name);
                export_data = Some(ed);
            }
            if let &Some(import_table) = optional_header.data_directories.get_import_table() {
                let id = import::ImportData::parse(bytes, &import_table, &sections)?;
                imports = import::Import::parse(bytes, &id, &sections)?;
                libraries = id.import_data.iter().map( | data | { data.name }).collect::<Vec<&'a str>>();
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
            is_64: is_64,
            entry: entry,
            image_base: image_base,
            export_data: export_data,
            import_data: import_data,
            exports: exports,
            imports: imports,
            libraries: libraries,
        })
    }
}
