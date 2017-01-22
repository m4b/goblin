use pe::error::*;
use super::data_directories;

use scroll;

/// standard COFF fields
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct StandardFields {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32, // no these are all the same u32, only base of data is absent seems: all below mabye 64-bit addr
    pub size_of_initialized_data: u32, // addr
    pub size_of_uninitialized_data: u32, // addr
    pub address_of_entry_point: u32, // addr
    pub base_of_code: u32, // addr
    /// absent in 64-bit PE32+
    pub base_of_data: u32,
}

pub const SIZEOF_STANDARD_FIELDS: usize = (3 * 8) + 4;

pub const MAGIC_32: u16 = 0x10b;
// TODO: verify this
pub const MAGIC_64: u16 = 0x20b;

impl StandardFields {
    pub fn parse<B: scroll::Gread> (bytes: &B, offset: &mut usize) -> Result<Self> {
        let mut standard_fields = StandardFields::default();
        standard_fields.magic = bytes.gread(offset, scroll::LE)?;
        standard_fields.major_linker_version = bytes.gread(offset, scroll::LE)?;
        standard_fields.minor_linker_version = bytes.gread(offset, scroll::LE)?;
        standard_fields.size_of_code = bytes.gread(offset, scroll::LE)?;
        standard_fields.size_of_initialized_data = bytes.gread(offset, scroll::LE)?;
        standard_fields.size_of_uninitialized_data = bytes.gread(offset, scroll::LE)?;
        standard_fields.address_of_entry_point = bytes.gread(offset, scroll::LE)?;
        standard_fields.base_of_code = bytes.gread(offset, scroll::LE)?;
        standard_fields.base_of_data = bytes.gread(offset, scroll::LE)?;
        Ok(standard_fields)
    }
}

/// Windows specific fields
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct WindowsFields {
    pub image_base: u32, // u64; 64-bit
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32, // u64
    pub size_of_stack_commit: u32, // u64
    pub size_of_heap_reserve: u32, // u64
    pub size_of_heap_commit: u32, // u64
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

pub const SIZEOF_WINDOWS_FIELDS: usize = (8 * 8) + 4;

impl WindowsFields {
    pub fn parse<B: scroll::Gread> (bytes: &B, offset: &mut usize) -> Result<Self> {
        let mut windows_fields = WindowsFields::default();
        windows_fields.image_base = bytes.gread(offset, scroll::LE)?;
        windows_fields.section_alignment = bytes.gread(offset, scroll::LE)?;
        windows_fields.file_alignment = bytes.gread(offset, scroll::LE)?;
        windows_fields.major_operating_system_version = bytes.gread(offset, scroll::LE)?;
        windows_fields.minor_operating_system_version = bytes.gread(offset, scroll::LE)?;
        windows_fields.major_image_version = bytes.gread(offset, scroll::LE)?;
        windows_fields.minor_image_version = bytes.gread(offset, scroll::LE)?;
        windows_fields.major_subsystem_version = bytes.gread(offset, scroll::LE)?;
        windows_fields.minor_subsystem_version = bytes.gread(offset, scroll::LE)?;
        windows_fields.win32_version_value = bytes.gread(offset, scroll::LE)?;
        windows_fields.size_of_image = bytes.gread(offset, scroll::LE)?;
        windows_fields.size_of_headers = bytes.gread(offset, scroll::LE)?;
        windows_fields.check_sum = bytes.gread(offset, scroll::LE)?;
        windows_fields.subsystem = bytes.gread(offset, scroll::LE)?;
        windows_fields.dll_characteristics = bytes.gread(offset, scroll::LE)?;
        windows_fields.size_of_stack_reserve = bytes.gread(offset, scroll::LE)?;
        windows_fields.size_of_stack_commit = bytes.gread(offset, scroll::LE)?;
        windows_fields.size_of_heap_reserve = bytes.gread(offset, scroll::LE)?;
        windows_fields.size_of_heap_commit = bytes.gread(offset, scroll::LE)?;
        windows_fields.loader_flags = bytes.gread(offset, scroll::LE)?;
        windows_fields.number_of_rva_and_sizes = bytes.gread(offset, scroll::LE)?;
        Ok(windows_fields)
    }
}



#[derive(Debug, PartialEq, Copy, Clone)]
pub struct OptionalHeader {
    pub standard_fields: StandardFields,
    pub windows_fields: WindowsFields,
    //pub data_directories: data_directories::DataDirectories
}

impl OptionalHeader {
    pub fn parse<B: scroll::Gread> (bytes: &B, offset: &mut usize) -> Result<Self> {
        let standard_fields = StandardFields::parse(bytes, offset)?;
        let windows_fields = WindowsFields::parse(bytes, offset)?;
        //let data_directories = data_directories::DataDirectories::parse(bytes, windows_fields.number_of_rva_and_sizes as usize, offset)?;
        Ok (OptionalHeader {
            standard_fields: standard_fields,
            windows_fields: windows_fields, 
            //data_directories: data_directories,
        })
    }
}
