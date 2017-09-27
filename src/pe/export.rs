use scroll::{self, Pread};

use error;

use pe::utils;
use pe::section_table;
use pe::data_directories;

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
    pub fn parse(bytes: &[u8], offset: usize) -> error::Result<Self> {
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
pub struct ExportData<'a> {
    pub name: &'a str,
    pub export_directory_table: ExportDirectoryTable,
    pub export_name_pointer_table: ExportNamePointerTable,
    pub export_ordinal_table: ExportOrdinalTable,
    pub export_address_table: ExportAddressTable,
}

impl<'a> ExportData<'a> {
    pub fn parse(bytes: &'a [u8], dd: &data_directories::DataDirectory, sections: &[section_table::SectionTable]) -> error::Result<ExportData<'a>> {
        let export_rva = dd.virtual_address as usize;
        let size = dd.size as usize;
        debug!("export_rva {:#x} size {:#}", export_rva, size);
        let export_offset = utils::find_offset_or(export_rva, sections, &format!("Cannot map export_rva ({:#x}) into offset", export_rva))?;
        let export_directory_table = ExportDirectoryTable::parse(bytes, export_offset)?;
        let number_of_name_pointers = export_directory_table.number_of_name_pointers as usize;
        let address_table_entries = export_directory_table.address_table_entries as usize;
        //let ordinal_base = export_directory_table.ordinal_base as usize;

        let name_pointer_table_offset = &mut utils::find_offset_or(export_directory_table.name_pointer_rva as usize, sections, &format!("Cannot map export_directory_table.name_pointer_rva ({:#x}) into offset", export_directory_table.name_pointer_rva))?;
        let mut export_name_pointer_table: ExportNamePointerTable = Vec::with_capacity(number_of_name_pointers);
        for _ in 0..number_of_name_pointers {
            export_name_pointer_table.push(bytes.gread_with(name_pointer_table_offset, scroll::LE)?);
        }

        let export_ordinal_table_offset = &mut utils::find_offset_or(export_directory_table.ordinal_table_rva as usize, sections, &format!("Cannot map export_directory_table.ordinal_table_rva ({:#x}) into offset", export_directory_table.ordinal_table_rva))?;
        let mut export_ordinal_table: ExportOrdinalTable = Vec::with_capacity(number_of_name_pointers);
        for _ in 0..number_of_name_pointers {
            export_ordinal_table.push(bytes.gread_with(export_ordinal_table_offset, scroll::LE)?);
        }

        let export_address_table_offset = utils::find_offset_or(export_directory_table.export_address_table_rva as usize, sections, &format!("Cannot map export_directory_table.export_address_table_rva ({:#x}) into offset", export_directory_table.export_address_table_rva))?;
        let export_end = export_rva + size;
        let offset = &mut export_address_table_offset.clone();
        let mut export_address_table: ExportAddressTable = Vec::with_capacity(address_table_entries);
        for _ in 0..address_table_entries {
            let rva: u32 = bytes.gread_with(offset, scroll::LE)?;
            if utils::is_in_range(rva as usize, export_rva, export_end) {
                export_address_table.push(ExportAddressTableEntry::ForwarderRVA(rva));
            } else {
                export_address_table.push(ExportAddressTableEntry::ExportRVA(rva));
            }
        }

        let name_offset = utils::find_offset_or(export_directory_table.name_rva as usize, sections, &format!("Cannot map export_directory_table.name_rva ({:#x}) into offset", export_directory_table.name_rva))?;
        debug!("ExportData.parse pointers: {:#x} ordinals: {:#x} addresses: {:#x}", name_pointer_table_offset, export_ordinal_table_offset, export_address_table_offset);
        let name: &'a str = bytes.pread(name_offset)?;
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
pub enum Reexport<'a> {
  DLLName { export: &'a str, lib: &'a str },
  DLLOrdinal { export: &'a str, ordinal: usize }
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for Reexport<'a> {
    type Error = ::error::Error;
    type Size = usize;
    #[inline]
    fn try_from_ctx(bytes: &'a [u8], _ctx: scroll::Endian) -> Result<(Self, Self::Size), Self::Error> {
        use scroll::{Pread};
        let reexport = bytes.pread::<&str>(0)?;
        let reexport_len = reexport.len();
        debug!("reexport: {}", &reexport);
        for o in 0..reexport_len {
            let c: u8 = bytes.pread(o)?;
            debug!("reexport offset: {:#x} char: {:#x}", o, c);
            match c {
                // '.'
                0x2e => {
                    let i = o - 1;
                    let dll: &'a str = bytes.pread_with(0, ::scroll::ctx::StrCtx::Length(i))?;
                    debug!("dll: {:?}", &dll);
                    let len = reexport_len - i - 1;
                    let rest: &'a [u8] = bytes.pread_with(o, len)?;
                    debug!("rest: {:?}", &rest);
                    let len = rest.len() - 1;
                    match rest[0] {
                        // '#'
                        0x23 => {
                            // UNTESTED
                            let ordinal = rest.pread_with::<&str>(1, ::scroll::ctx::StrCtx::Length(len))?;
                            let ordinal = ordinal.parse::<u32>().map_err(|_e| error::Error::Malformed(format!("Cannot parse reexport ordinal from {} bytes", bytes.len())))?;
                            // FIXME: return size
                            return Ok((Reexport::DLLOrdinal { export: dll, ordinal: ordinal as usize }, 0))
                        },
                        _ => {
                            let export = rest.pread_with::<&str>(1, ::scroll::ctx::StrCtx::Length(len))?;
                            // FIXME: return size
                            return Ok((Reexport::DLLName { export: export, lib: dll }, 0))
                        }
                    }
                },
                _ => {}
            }
        }
        Err(error::Error::Malformed(format!("Reexport {:#} is malformed", reexport)))
    }
}

impl<'a> Reexport<'a> {
    pub fn parse(bytes: &'a [u8], offset: usize) -> ::error::Result<Reexport<'a>> {
        bytes.pread(offset)
    }
}

#[derive(Debug, Default)]
/// An exported symbol in this binary, contains synthetic data (name offset, etc., are computed)
pub struct Export<'a> {
    pub name: &'a str,
    pub offset: usize,
    pub rva: usize,
    pub size: usize,
    pub reexport: Option<Reexport<'a>>,
}

#[derive(Debug, Copy, Clone)]
struct ExportCtx<'a> {
    pub ptr: u32,
    pub idx: usize,
    pub sections: &'a [section_table::SectionTable],
    pub addresses: &'a ExportAddressTable,
    pub ordinals: &'a ExportOrdinalTable,
}

impl<'a, 'b> scroll::ctx::TryFromCtx<'a, ExportCtx<'b>> for Export<'a> {
    type Error = error::Error;
    type Size = usize;
    #[inline]
    fn try_from_ctx(bytes: &'a [u8], ExportCtx { ptr, idx, sections, addresses, ordinals }: ExportCtx<'b>) -> Result<(Self, Self::Size), Self::Error> {
        use self::ExportAddressTableEntry::*;
        let i = idx;
        let name_offset = utils::find_offset_or(ptr as usize, sections, &format!("Cannot map export name pointer rva ({:#x}) into offset", ptr))?;
        let name = bytes.pread::<&str>(name_offset)?;
        let ordinal = ordinals[i];
        let address_index = ordinal as usize;
        debug!("name: {} name_offset: {:#x} ordinal: {} address_index: {}", name, name_offset, ordinal, address_index);
        if address_index >= addresses.len() {
            debug!("Export.pread bad address index ({}) for {}: idx: {} ordinal: {} addresses.len(): {}", name, address_index, i, ordinal, addresses.len());
            Ok((Export::default(), 0))
        } else {
            match addresses[address_index] {
                ExportRVA(rva) => {
                    let rva = rva as usize;
                    let offset = utils::find_offset_or(rva, sections, &format!("Cannot map export rva ({:#x}) into offset for {}", rva, name))?;
                    debug!("{}: {:#x}", name, offset);
                    Ok((Export { name: name, offset: offset, rva: rva, reexport: None, size: 0 }, 0))
                },
                ForwarderRVA(rva) => {
                    let rva = rva as usize;
                    let offset = utils::find_offset_or(rva, sections, &format!("Cannot map forwarder rva ({:#x}) into offset for {}", rva, name))?;
                    debug!("{}: stroffset {:#x}", name, offset);
                    let reexport = Reexport::parse(bytes, offset)?;
                    debug!("{}: reexport {:?}", name, reexport);
                    Ok((Export { name: name, offset: rva, rva: rva, reexport: Some(reexport), size: 0 }, 0))
                },
            }
        }
    }
}

impl<'a> Export<'a> {
    pub fn parse(bytes: &'a [u8], export_data: &ExportData, sections: &[section_table::SectionTable]) -> error::Result<Vec<Export<'a>>> {
        let pointers = &export_data.export_name_pointer_table;
        let addresses = &export_data.export_address_table;
        let ordinals = &export_data.export_ordinal_table;
        //let ordinal_base = export_data.export_directory_table.ordinal_base as usize;
        let mut exports = Vec::with_capacity(pointers.len());
        for (idx, ptr) in pointers.iter().enumerate() {
            let export = bytes.pread_with(0, ExportCtx { ptr: *ptr, idx: idx, sections: sections, addresses: addresses, ordinals: ordinals })?;
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
