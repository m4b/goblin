use pe::error::*;
use scroll;

use super::utils;
use super::section_table;
use super::data_directories;

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct ExportDirectoryTable {
    pub export_flags: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name_rva: u32,
    pub ordinal_base: u32,
    pub address_table_entries: u32,
    pub number_of_name_pointers: u32,
    pub export_address_table_rva: u32,
    pub name_pointer_rva: u32,
    pub ordinal_table_rva: u32,
}

pub const SIZEOF_EXPORT_DIRECTORY_TABLE: usize = 40;

impl ExportDirectoryTable {
    pub fn parse<B: scroll::Gread>(bytes: &B, offset: usize) -> Result<Self> {
        let mut table = ExportDirectoryTable::default();
        let mut offset = &mut (offset.clone());
        table.export_flags = bytes.gread(offset, scroll::LE)?;
        table.time_date_stamp = bytes.gread(offset, scroll::LE)?;
        table.major_version = bytes.gread(offset, scroll::LE)?;
        table.minor_version = bytes.gread(offset, scroll::LE)?;
        table.name_rva = bytes.gread(offset, scroll::LE)?;
        table.ordinal_base = bytes.gread(offset, scroll::LE)?;
        table.address_table_entries = bytes.gread(offset, scroll::LE)?;
        table.number_of_name_pointers = bytes.gread(offset, scroll::LE)?;
        table.export_address_table_rva = bytes.gread(offset, scroll::LE)?;
        table.name_pointer_rva = bytes.gread(offset, scroll::LE)?;
        table.ordinal_table_rva = bytes.gread(offset, scroll::LE)?;
        Ok (table)
    }
}

#[derive(Debug)]
pub enum ExportAddressTableEntry {
  ExportRVA(u32),
  ForwarderRVA(u32),
}

pub const SIZEOF_EXPORT_ADDRESS_TABLE_ENTRY: usize = 4;

pub type ExportAddressTable = Vec<ExportAddressTableEntry>;

// array of rvas into the export name table; export name is defined iff pointer table has pointer to the name
pub type ExportNamePointerTable = Vec<u32>;

// array of indexes into the export addres table idx = ordinal - ordinalbase
pub type ExportOrdinalTable = Vec<u16>;

#[derive(Debug, Default)]
pub struct ExportData {
    pub export_directory_table: ExportDirectoryTable,
    pub export_name_pointer_table: ExportNamePointerTable,
    pub export_ordinal_table: ExportOrdinalTable,
    pub export_address_table: ExportAddressTable,
    pub name: String
}

impl ExportData {
    pub fn parse<B: scroll::Gread>(bytes: &B, dd: &data_directories::DataDirectory, sections: &[section_table::SectionTable]) -> Result<Self> {
        let export_rva = dd.virtual_address as usize;
        let size = dd.size as usize;
        let export_offset = utils::find_offset(export_rva, sections).unwrap();
        let export_directory_table = ExportDirectoryTable::parse(bytes, export_offset)?;
        let number_of_name_pointers = export_directory_table.number_of_name_pointers as usize;
        let address_table_entries = export_directory_table.address_table_entries as usize;

        let mut name_pointer_table_offset = &mut utils::find_offset(export_directory_table.name_pointer_rva as usize, sections).unwrap();
        let mut export_name_pointer_table: ExportNamePointerTable = Vec::with_capacity(number_of_name_pointers);
        for _ in 0..number_of_name_pointers {
            export_name_pointer_table.push(bytes.gread(name_pointer_table_offset, scroll::LE)?);
        }

        let mut export_ordinal_table_offset = &mut utils::find_offset(export_directory_table.ordinal_table_rva as usize, sections).unwrap();
        let mut export_ordinal_table: ExportOrdinalTable = Vec::with_capacity(number_of_name_pointers);
        for _ in 0..number_of_name_pointers {
            export_ordinal_table.push(bytes.gread(export_ordinal_table_offset, scroll::LE)?);
        }

        let mut export_address_table_offset = &mut utils::find_offset(export_directory_table.export_address_table_rva as usize, sections).unwrap();
        // let mut export_address_table: ExportAddressTable = Vec::with_capacity();
        // for _ in 0..number_of_name_pointers {
        //     name_pointers.push(bytes.gread(name_pointer_table_offset, scroll::LE)?);
        // }

        let name_offset = utils::find_offset(export_directory_table.name_rva as usize, sections);
        println!("<PEExport.get> pointers: 0x{:x}  ordinals: 0x{:x} addresses: 0x{:x}", name_pointer_table_offset, export_ordinal_table_offset, export_address_table_offset);
        unimplemented!();
    }
}

#[derive(Debug)]
pub enum Reexport {
  DLLName ((String, String)),
  DLLOrdinal ((String, usize))
}

#[derive(Debug, Default)]
pub struct Export {
    name: String,
    offset: usize,
    rva: usize,
    size: usize,
    reexport: Option<Reexport>,
}
