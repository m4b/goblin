use scroll::{self, Pread, Gread};
use error;

use pe::section_table;
use pe::utils;
use pe::data_directories;

#[derive(Debug, Clone)]
pub struct HintNameTableEntry {
    pub hint: u16,
    pub name: String,
}

impl HintNameTableEntry {
    fn parse(bytes: &[u8], mut offset: usize) -> error::Result<Self> {
        let mut offset = &mut offset;
        let hint = bytes.gread_with(offset, scroll::LE)?;
        let name = bytes.pread::<&str>(*offset)?.to_string();
        Ok(HintNameTableEntry { hint: hint, name: name })
    }
}

#[derive(Debug, Clone)]
pub enum SyntheticImportLookupTableEntry {
    OrdinalNumber(u16),
    HintNameTableRVA ((u32, HintNameTableEntry)), // [u8; 31] bitfield :/
}

#[derive(Debug)]
pub struct ImportLookupTableEntry {
    pub bitfield: u32,
    pub synthetic: SyntheticImportLookupTableEntry,
}

pub type ImportLookupTable = Vec<ImportLookupTableEntry>;

pub const IMPORT_BY_ORDINAL_32: u32 = 0x8000_0000;
pub const IMPORT_RVA_MASK_32: u32 = 0x8fff_ffff;

impl ImportLookupTableEntry {
    pub fn parse(bytes: &[u8], mut offset: usize, sections: &[section_table::SectionTable])
                                                                      -> error::Result<ImportLookupTable> {
        let le = scroll::LE;
        let mut offset = &mut offset;
        let mut table = Vec::new();
        loop {
            let bitfield: u32 = bytes.gread_with(offset, le)?;
            if bitfield == 0 {
                //println!("imports done");
                break;
            } else {
                let synthetic = {
                    use self::SyntheticImportLookupTableEntry::*;
                    if bitfield & IMPORT_BY_ORDINAL_32 == IMPORT_BY_ORDINAL_32 {
                        let ordinal = (0xffff & bitfield) as u16;
                        //println!("importing by ordinal {:#x}", ordinal);
                        OrdinalNumber(ordinal)
                    } else {
                        let rva = bitfield & IMPORT_RVA_MASK_32;
                        let hentry = {
                            //println!("searching for RVA {:#x}", rva);
                            let offset = utils::find_offset(rva as usize, sections).unwrap();
                            //println!("offset {:#x}", offset);
                            HintNameTableEntry::parse(bytes, offset)?
                            //HintNameTableEntry {hint = 0; name = "".to_string()}
                        };
                        HintNameTableRVA ((rva, hentry))
                    }
                };
                let entry = ImportLookupTableEntry { bitfield: bitfield, synthetic: synthetic };
                table.push(entry);
            }
        }
        Ok(table)
    }
}

// get until entry is 0
pub type ImportAddressTable = Vec<u32>;

pub const SIZEOF_IMPORT_ADDRESS_TABLE_ENTRY: usize = 4;

#[repr(C)]
#[derive(Debug)]
#[derive(Pread, Pwrite, SizeWith)]
pub struct ImportDirectoryEntry {
    pub import_lookup_table_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub import_address_table_rva: u32,
}

pub const SIZEOF_IMPORT_DIRECTORY_ENTRY: usize = 20;

impl ImportDirectoryEntry {
    pub fn is_null (&self) -> bool {
        (self.import_lookup_table_rva == 0) &&
            (self.time_date_stamp == 0) &&
            (self.forwarder_chain == 0) &&
            (self.name_rva == 0) &&
            (self.import_address_table_rva == 0)
    }
}

#[derive(Debug)]
pub struct SyntheticImportDirectoryEntry {
    pub import_directory_entry: ImportDirectoryEntry,
    /// Computed
    pub name: String,
    /// Computed
    pub import_lookup_table: ImportLookupTable,
    /// Computed
    pub import_address_table: ImportAddressTable,
}

impl SyntheticImportDirectoryEntry {
    pub fn parse(bytes: &[u8], import_directory_entry: ImportDirectoryEntry, sections: &[section_table::SectionTable]) -> error::Result<Self> {
        let le = scroll::LE;
        let name_rva = import_directory_entry.name_rva;
        let name = utils::try_name(bytes, name_rva as usize, sections)?.to_string();
        let import_lookup_table_rva = import_directory_entry.import_lookup_table_rva;
        let import_lookup_table_offset = utils::find_offset(import_lookup_table_rva as usize, sections).unwrap();
        let import_lookup_table = ImportLookupTableEntry::parse(bytes, import_lookup_table_offset, sections)?;
        let import_address_table_offset = &mut utils::find_offset(import_directory_entry.import_address_table_rva as usize, sections).unwrap();
        let mut import_address_table = Vec::new();
        loop {
            let import_address = bytes.gread_with(import_address_table_offset, le)?;
            if import_address == 0 { break } else { import_address_table.push(import_address); }
        }
        Ok(SyntheticImportDirectoryEntry {
            import_directory_entry: import_directory_entry,
            name: name,
            import_lookup_table: import_lookup_table,
            import_address_table: import_address_table
        })
    }
}

#[derive(Debug)]
/// Contains a list of synthesized import data for this binary, e.g., which symbols from which libraries it is importing from
pub struct ImportData {
    pub import_data: Vec<SyntheticImportDirectoryEntry>,
}

impl ImportData {
    pub fn parse(bytes: &[u8], dd: &data_directories::DataDirectory, sections: &[section_table::SectionTable]) -> error::Result<Self> {
        let import_directory_table_rva = dd.virtual_address as usize;
        let mut offset = &mut utils::find_offset(import_directory_table_rva, sections).unwrap();
        let mut import_data = Vec::new();
        loop {
            let import_directory_entry: ImportDirectoryEntry = bytes.gread_with(offset, scroll::LE)?;
            if import_directory_entry.is_null() {
                break;
            } else {
                let entry = SyntheticImportDirectoryEntry::parse(bytes, import_directory_entry, sections)?;
                import_data.push(entry);
            }
        }
        //println!("finished import directory table");
        Ok(ImportData { import_data: import_data})
    }
}

#[derive(Debug)]
/// A synthesized symbol import, the name is pre-indexed, and the binary offset is computed, as well as which dll it belongs to
pub struct Import {
    pub name: String,
    pub dll: String,
    pub ordinal: u16,
    pub offset: usize,
    pub rva: usize,
    pub size: usize,
}

impl Import {
    pub fn parse(_bytes: &[u8], import_data: &ImportData, _sections: &[section_table::SectionTable]) -> error::Result<Vec<Self>> {
        let mut imports = Vec::new();
        for data in &import_data.import_data {
            let import_lookup_table = &data.import_lookup_table;
            // fixme don't copy
            let dll = data.name.to_owned();
            let import_base = data.import_directory_entry.import_address_table_rva as usize;
            //println!("getting imports from {}", &dll);
            for (i, entry) in import_lookup_table.iter().enumerate() {
                let offset = import_base + (i * SIZEOF_IMPORT_ADDRESS_TABLE_ENTRY);
                use self::SyntheticImportLookupTableEntry::*;
                let (rva, name, ordinal) =
                    match &entry.synthetic {
                        &HintNameTableRVA ((rva, ref hint_entry)) => {
                            let res = (rva, hint_entry.name.to_owned(), hint_entry.hint.clone());
                            // if hint_entry.name = "" && hint_entry.hint = 0 {
                            //     println!("<PE.Import> warning hint/name table rva from {} without hint {:#x}", dll, rva);
                            // }
                            res
                        },
                        &OrdinalNumber(ordinal) => {
                            let name = format!("ORDINAL {}", ordinal);
                            (0x0, name, ordinal)
                        }
                    };
                let import =
                    Import {
                        name: name,
                        ordinal: ordinal, dll: dll.to_owned(),
                        size: 4, offset: offset, rva: rva as usize
                    };
                imports.push(import);
            }
        }
        Ok (imports)
    }
}
