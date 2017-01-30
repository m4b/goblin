use scroll;

use pe::error;

use super::utils;
use super::section_table;
use super::data_directories;

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
#[derive(Pread, Pwrite)]
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
    pub fn parse<B: scroll::Gread>(bytes: &B, offset: usize) -> error::Result<Self> {
        let res = bytes.pread_with(offset, scroll::LE)?;
        Ok(res)
    }
}

#[derive(Debug)]
pub enum ExportAddressTableEntry {
  ExportRVA(u32),
  ForwarderRVA(u32),
}

pub const SIZEOF_EXPORT_ADDRESS_TABLE_ENTRY: usize = 4;

pub type ExportAddressTable = Vec<ExportAddressTableEntry>;

/// Array of rvas into the export name table
///
/// Export name is defined iff pointer table has pointer to the name
pub type ExportNamePointerTable = Vec<u32>;

/// Array of indexes into the export address table.
///
/// Should obey the formula `idx = ordinal - ordinalbase`
pub type ExportOrdinalTable = Vec<u16>;

#[derive(Debug, Default)]
/// Export data contains the `dll` name which other libraries can import symbols by (two-level namespace), as well as other important indexing data allowing symbol lookups
pub struct ExportData {
    pub name: String,
    pub export_directory_table: ExportDirectoryTable,
    pub export_name_pointer_table: ExportNamePointerTable,
    pub export_ordinal_table: ExportOrdinalTable,
    pub export_address_table: ExportAddressTable,
}

impl ExportData {
    pub fn parse<B: scroll::Gread>(bytes: &B, dd: &data_directories::DataDirectory, sections: &[section_table::SectionTable]) -> error::Result<Self> {
        let export_rva = dd.virtual_address as usize;
        let size = dd.size as usize;
        let export_offset = utils::find_offset(export_rva, sections).unwrap();
        let export_directory_table = ExportDirectoryTable::parse(bytes, export_offset)?;
        let number_of_name_pointers = export_directory_table.number_of_name_pointers as usize;
        let address_table_entries = export_directory_table.address_table_entries as usize;
        //let ordinal_base = export_directory_table.ordinal_base as usize;

        let mut name_pointer_table_offset = &mut utils::find_offset(export_directory_table.name_pointer_rva as usize, sections).unwrap();
        let mut export_name_pointer_table: ExportNamePointerTable = Vec::with_capacity(number_of_name_pointers);
        for _ in 0..number_of_name_pointers {
            export_name_pointer_table.push(bytes.gread_with(name_pointer_table_offset, scroll::LE)?);
        }

        let mut export_ordinal_table_offset = &mut utils::find_offset(export_directory_table.ordinal_table_rva as usize, sections).unwrap();
        let mut export_ordinal_table: ExportOrdinalTable = Vec::with_capacity(number_of_name_pointers);
        for _ in 0..number_of_name_pointers {
            export_ordinal_table.push(bytes.gread_with(export_ordinal_table_offset, scroll::LE)?);
        }

        let export_address_table_offset = utils::find_offset(export_directory_table.export_address_table_rva as usize, sections).unwrap();
        let export_end = export_rva + size;
        let mut offset = &mut export_address_table_offset.clone();
        let mut export_address_table: ExportAddressTable = Vec::with_capacity(address_table_entries);
        for _ in 0..address_table_entries {
            let rva: u32 = bytes.gread_with(offset, scroll::LE)?;
            if utils::is_in_range(rva as usize, export_rva, export_end) {
                export_address_table.push(ExportAddressTableEntry::ForwarderRVA(rva));
            } else {
                export_address_table.push(ExportAddressTableEntry::ExportRVA(rva));
            }
        }

        let name_offset = utils::find_offset(export_directory_table.name_rva as usize, sections).unwrap();
        //println!("<PEExport.get> pointers: 0x{:x}  ordinals: 0x{:x} addresses: 0x{:x}", name_pointer_table_offset, export_ordinal_table_offset, export_address_table_offset);
        let name = bytes.pread_slice::<str>(name_offset, 8)?.to_string();
        Ok(ExportData {
            name: name,
            export_directory_table: export_directory_table,
            export_name_pointer_table: export_name_pointer_table,
            export_ordinal_table: export_ordinal_table,
            export_address_table: export_address_table,
        })
    }
}

#[derive(Debug)]
/// PE binaries have two kinds of reexports, either specifying the dll's name, or the ordinal value of the dll
pub enum Reexport {
  DLLName ((String, String)),
  DLLOrdinal ((String, usize))
}

// this compiles but cannot be used due to sized requirements which i don't understand :tada:
impl<'a, B: ?Sized> scroll::ctx::TryFromCtx<'a, (usize, scroll::ctx::DefaultCtx), B> for Reexport
    where B: scroll::Gread + scroll::Gread<scroll::Error, scroll::ctx::StrCtx> + AsRef<[u8]> {
    type Error = scroll::Error;
    #[inline]
    fn try_from_ctx(bytes: &'a B, (offset, _): (usize, scroll::ctx::DefaultCtx)) -> Result<Self, Self::Error> {
        use scroll::{Gread, Pread};
        let bytes = bytes.as_ref();
        let reexport: &str = bytes.pread::<&str>(offset)?;
        println!("reexport: {}", &reexport);
        let bytes: &[u8] = reexport.as_bytes();
        let mut o = &mut 0;
        loop {
            let c: u8 = bytes.gread(o)?;
            println!("reexport offset: {:#x} char: {:#x}", *o, c);
            match c {
                // '.'
                0x2e => {
                    let i = *o - 1;
                    let dll: &str = bytes.pread_slice(0, i)?;
                    println!("dll: {:?}", &dll);
                    let len = reexport.len() - i - 1;
                    let rest: &[u8] = bytes.gread_slice(o, len)?;
                    println!("rest: {:?}", &rest);
                    match rest[0] {
                        // '#'
                        0x23 => {
                            // UNTESTED
                            let len = rest.len() - 1;
                            let ordinal = rest.pread_slice::<str>(1, len)?;
                            let ordinal = ordinal.parse::<u32>().unwrap();
                            return Ok(Reexport::DLLOrdinal ((dll.to_string(), ordinal as usize)))
                        },
                        _ => {
                            let rest = rest.pread_slice::<str>(0, rest.len())?;
                            return Ok(Reexport::DLLName ((dll.to_string(), rest.to_string())))
                        }
                    }
                },
                _ => {}
            }
        }
    }
}

impl Reexport {
    pub fn parse<B: scroll::Gread + scroll::Gread<scroll::Error, scroll::ctx::StrCtx>>(bytes: &B, offset: usize) -> scroll::Result<Reexport> {
        use scroll::{Gread, Pread};
        let reexport: &str = bytes.pread::<&str>(offset)?;
        //println!("reexport: {}", &reexport);
        let bytes: &[u8] = reexport.as_bytes();
        let mut o = &mut 0;
        loop {
            let c: u8 = bytes.gread(o)?;
            //println!("reexport offset: {:#x} char: {:#x}", *o, c);
            match c {
                // '.'
                0x2e => {
                    let i = *o - 1;
                    let dll: &str = bytes.pread_slice(0, i)?;
                    //println!("dll: {:?}", &dll);
                    let len = reexport.len() - i - 1;
                    let rest: &[u8] = bytes.gread_slice(o, len)?;
                    //println!("rest: {:?}", &rest);
                    match rest[0] {
                        // '#'
                        0x23 => {
                            // UNTESTED
                            let len = rest.len() - 1;
                            let ordinal = rest.pread_slice::<str>(1, len)?;
                            let ordinal = ordinal.parse::<u32>().unwrap();
                            return Ok(Reexport::DLLOrdinal ((dll.to_string(), ordinal as usize)))
                        },
                        _ => {
                            let rest = rest.pread_slice::<str>(0, rest.len())?;
                            return Ok(Reexport::DLLName ((dll.to_string(), rest.to_string())))
                        }
                    }
                },
                _ => {}
            }
        }
    }
}

#[derive(Debug, Default)]
/// An exported symbol in this binary, contains synthetic data (name offset, etc., are computed)
pub struct Export {
    pub name: String,
    pub offset: usize,
    pub rva: usize,
    pub size: usize,
    pub reexport: Option<Reexport>,
}

#[derive(Debug, Copy, Clone)]
struct ExportCtx<'a> {
    pub ptr: u32,
    pub idx: usize,
    pub sections: &'a [section_table::SectionTable],
    pub addresses: &'a ExportAddressTable,
    pub ordinals: &'a ExportOrdinalTable,
}

impl<'a, B> scroll::ctx::TryFromCtx<'a, ExportCtx<'a>, B> for Export where B: scroll::Gread + scroll::Gread<scroll::Error, scroll::ctx::StrCtx> {
    type Error = scroll::Error;
    #[inline]
    fn try_from_ctx(bytes: &'a B, ExportCtx { ptr, idx, sections, addresses, ordinals }: ExportCtx<'a>) -> Result<Self, Self::Error> {
        use self::ExportAddressTableEntry::*;
        let i = idx;
        let name_offset = utils::find_offset(ptr as usize, sections).unwrap();
        let name = bytes.pread::<&str>(name_offset)?.to_string();
        let ordinal = ordinals[i];
        let address_index = ordinal as usize;
        //println!("name: {} name_offset: {:#x} ordinal: {} address_index: {}", name, name_offset, ordinal, address_index);
        if address_index >= addresses.len() {
            //println!("<PEExport.get_export> bad index for {}: {} {} {} len: {}", name, (i+ordinal_base), ordinal, address_index, addresses.len());
            Ok(Export::default())
        } else {
            match addresses[address_index] {
                ExportRVA(rva) => {
                    let rva = rva as usize;
                    let offset = utils::find_offset(rva, sections).unwrap();
                    //println!("{:#x}", offset);
                    Ok(Export { name: name, offset: offset, rva: rva, reexport: None, size: 0 })
                },
                ForwarderRVA(rva) => {
                    let rva = rva as usize;
                    let offset = utils::find_offset(rva, sections).unwrap();
                    //println!("stroffset {:#x}", offset);
                    let reexport = Reexport::parse(bytes, offset)?;
                    // cannot use this for reasons above cause rust is super fun
                    //let reexport = bytes.pread(offset)?;
                    Ok(Export { name: name, offset: rva, rva: rva, reexport: Some(reexport), size: 0 })
                },
            }
        }
    }
}

impl Export {
    pub fn parse<B: scroll::Gread + scroll::Gread<scroll::Error, scroll::ctx::StrCtx>>(bytes: &B, export_data: &ExportData, sections: &[section_table::SectionTable]) -> error::Result<Vec<Export>> {
        let pointers = &export_data.export_name_pointer_table;
        let addresses = &export_data.export_address_table;
        let ordinals = &export_data.export_ordinal_table;
        //let ordinal_base = export_data.export_directory_table.ordinal_base as usize;
        let mut exports = Vec::with_capacity(pointers.len());
        for (idx, ptr) in pointers.iter().enumerate() {
            use scroll::ctx::TryFromCtx;
            let export = Export::try_from_ctx(bytes, ExportCtx { ptr: *ptr, idx: idx, sections: sections, addresses: addresses, ordinals: ordinals })?;
            exports.push(export);
        }
        // TODO: sort + compute size
        Ok (exports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_export_directory_table() {
        assert_eq!(::std::mem::size_of::<ExportDirectoryTable>(), SIZEOF_EXPORT_DIRECTORY_TABLE);
    }
}
