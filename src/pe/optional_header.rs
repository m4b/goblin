use container;
use error;

use super::{utils::{self, CStructCtx}, section_table, data_directories};
use scroll::{ctx, LE, Pread};
use core::mem;

pub const SIZEOF_STANDARD_FIELDS_32: usize = 28;

implement_ctx_cstruct! {
    struct StandardFields32 {
        magic: u16,
        major_linker_version: u8,
        minor_linker_version: u8,
        size_of_code: u32,
        size_of_initialized_data: u32,
        size_of_uninitialized_data: u32,
        address_of_entry_point: u32,
        base_of_code: u32,
        base_of_data: u32,
    }
}

pub const SIZEOF_STANDARD_FIELDS_64: usize = 24;

implement_ctx_cstruct! {
    struct StandardFields64 {
        magic: u16,
        major_linker_version: u8,
        minor_linker_version: u8,
        size_of_code: u32,
        size_of_initialized_data: u32,
        size_of_uninitialized_data: u32,
        address_of_entry_point: u32,
        base_of_code: u32,
    }   
}

/// Unified 32/64-bit COFF fields
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct StandardFields {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u64,
    pub size_of_initialized_data: u64,
    pub size_of_uninitialized_data: u64,
    pub address_of_entry_point: u64,
    pub base_of_code: u64,
    /// absent in 64-bit PE32+
    pub base_of_data: u32,
}

impl From<StandardFields32> for StandardFields {
    fn from(fields: StandardFields32) -> Self {
        StandardFields {
            magic: fields.magic,
            major_linker_version: fields.major_linker_version,
            minor_linker_version: fields.minor_linker_version,
            size_of_code: fields.size_of_code as u64,
            size_of_initialized_data: fields.size_of_initialized_data as u64,
            size_of_uninitialized_data: fields.size_of_uninitialized_data as u64,
            address_of_entry_point: fields.address_of_entry_point as u64,
            base_of_code: fields.base_of_code as u64,
            base_of_data: fields.base_of_data,
        }
    }
}

impl From<StandardFields64> for StandardFields {
    fn from(fields: StandardFields64) -> Self {
        StandardFields {
            magic: fields.magic,
            major_linker_version: fields.major_linker_version,
            minor_linker_version: fields.minor_linker_version,
            size_of_code: fields.size_of_code as u64,
            size_of_initialized_data: fields.size_of_initialized_data as u64,
            size_of_uninitialized_data: fields.size_of_uninitialized_data as u64,
            address_of_entry_point: fields.address_of_entry_point as u64,
            base_of_code: fields.base_of_code as u64,
            base_of_data: 0,
        }
    }
}

/// Standard fields magic number for 32-bit binary
pub const MAGIC_32: u16 = 0x10b;
/// Standard fields magic number for 64-bit binary
pub const MAGIC_64: u16 = 0x20b;

pub const SIZEOF_WINDOWS_FIELDS_32: usize = 68;

implement_ctx_cstruct! {
    struct WindowsFields32 {
        image_base: u32,
        section_alignment: u32,
        file_alignment: u32,
        major_operating_system_version: u16,
        minor_operating_system_version: u16,
        major_image_version: u16,
        minor_image_version: u16,
        major_subsystem_version: u16,
        minor_subsystem_version: u16,
        win32_version_value: u32,
        size_of_image: u32,
        size_of_headers: u32,
        check_sum: u32,
        subsystem: u16,
        dll_characteristics: u16,
        size_of_stack_reserve: u32,
        size_of_stack_commit: u32,
        size_of_heap_reserve: u32,
        size_of_heap_commit: u32,
        loader_flags: u32,
        number_of_rva_and_sizes: u32,
    }
}

pub const SIZEOF_WINDOWS_FIELDS_64: usize = 88;

implement_ctx_cstruct! {
    struct WindowsFields64 {
        image_base: u64,
        section_alignment: u32,
        file_alignment: u32,
        major_operating_system_version: u16,
        minor_operating_system_version: u16,
        major_image_version: u16,
        minor_image_version: u16,
        major_subsystem_version: u16,
        minor_subsystem_version: u16,
        win32_version_value: u32,
        size_of_image: u32,
        size_of_headers: u32,
        check_sum: u32,
        subsystem: u16,
        dll_characteristics: u16,
        size_of_stack_reserve: u64,
        size_of_stack_commit: u64,
        size_of_heap_reserve: u64,
        size_of_heap_commit: u64,
        loader_flags: u32,
        number_of_rva_and_sizes: u32,
    }
}

impl From<WindowsFields32> for WindowsFields {
    fn from(windows: WindowsFields32) -> Self {
        WindowsFields {
            image_base: windows.image_base as u64,
            section_alignment: windows.section_alignment,
            file_alignment: windows.file_alignment,
            major_operating_system_version: windows.major_operating_system_version,
            minor_operating_system_version: windows.minor_operating_system_version,
            major_image_version: windows.major_image_version,
            minor_image_version: windows.minor_image_version,
            major_subsystem_version: windows.major_subsystem_version,
            minor_subsystem_version: windows.minor_subsystem_version,
            win32_version_value: windows.win32_version_value,
            size_of_image: windows.size_of_image,
            size_of_headers: windows.size_of_headers,
            check_sum: windows.check_sum,
            subsystem: windows.subsystem,
            dll_characteristics: windows.dll_characteristics,
            size_of_stack_reserve: windows.size_of_stack_reserve as u64,
            size_of_stack_commit: windows.size_of_stack_commit as u64,
            size_of_heap_reserve: windows.size_of_heap_reserve as u64,
            size_of_heap_commit: windows.size_of_heap_commit as u64,
            loader_flags: windows.loader_flags,
            number_of_rva_and_sizes: windows.number_of_rva_and_sizes,
        }
    }
}

pub type WindowsFields = WindowsFields64;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct OptionalHeader {
    pub standard_fields: StandardFields,
    pub windows_fields: WindowsFields,
    pub data_directories: data_directories::DataDirectories
}

impl OptionalHeader {
    pub fn container(&self) -> error::Result<container::Container> {
        match self.standard_fields.magic {
            MAGIC_32 => {
                Ok(container::Container::Little)
            },
            MAGIC_64 => {
                Ok(container::Container::Big)
            },
            magic => {
                Err(error::Error::BadMagic(magic as u64))
            }
        }
    }
}

impl<'a, 'b> ctx::TryFromCtx<'a, CStructCtx<'b>> for OptionalHeader {
    type Error = error::Error;
    type Size = usize;
    fn try_from_ctx(bytes: &'a [u8], CStructCtx { ptr, sections }: CStructCtx<'b>) -> Result<(Self, Self::Size), Self::Error> {
        let offset = {
            let ptr = ptr as usize;
            &mut utils::find_offset(ptr, sections).unwrap_or(ptr)
        };
        let magic = bytes.pread_with::<u16>(*offset, LE)?;
        let (standard_fields, windows_fields, size): (StandardFields, WindowsFields, usize) = match magic {
            MAGIC_32 => {
                let standard_fields = StandardFields32::parse(bytes, offset, sections)?.into();
                let windows_fields = WindowsFields32::parse(bytes, offset, sections)?.into();
                (standard_fields, windows_fields, SIZEOF_STANDARD_FIELDS_32 + SIZEOF_WINDOWS_FIELDS_32)
            },

            MAGIC_64 => {
                let standard_fields = StandardFields64::parse(bytes, offset, sections)?.into();
                let windows_fields = WindowsFields64::parse(bytes, offset, sections)?.into();
                (standard_fields, windows_fields, SIZEOF_STANDARD_FIELDS_64 + SIZEOF_WINDOWS_FIELDS_64)
            },

            _ => return Err(error::Error::BadMagic(magic as u64))
        };

        let data_directories = data_directories::DataDirectories::parse(&bytes, windows_fields.number_of_rva_and_sizes as usize, offset, sections)?;
        Ok((OptionalHeader { standard_fields, windows_fields, data_directories }, size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sizeof_standards32() {
        assert_eq!(::std::mem::size_of::<StandardFields32>(), SIZEOF_STANDARD_FIELDS_32);
    }
    #[test]
    fn sizeof_windows32() {
        assert_eq!(::std::mem::size_of::<WindowsFields32>(), SIZEOF_WINDOWS_FIELDS_32);
    }
    #[test]
    fn sizeof_standards64() {
        assert_eq!(::std::mem::size_of::<StandardFields64>(), SIZEOF_STANDARD_FIELDS_64);
    }
    #[test]
    fn sizeof_windows64() {
        assert_eq!(::std::mem::size_of::<WindowsFields64>(), SIZEOF_WINDOWS_FIELDS_64);
    }
}
