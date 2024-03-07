use crate::container;
use crate::error;

use crate::pe::data_directories;

use scroll::{ctx, Endian, LE};
use scroll::{Pread, Pwrite, SizeWith};

/// Standard 32-bit COFF fields (for `PE32`).
///
/// In `winnt.h`, this is a subset of [`IMAGE_OPTIONAL_HEADER32`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32).
///
/// * For 64-bit version, see [`StandardFields64`].
/// * For unified version, see [`StandardFields`].
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct StandardFields32 {
    /// See docs for [`StandardFields::magic`](crate::pe::optional_header::StandardFields::magic).
    pub magic: u16,
    /// See docs for [`StandardFields::major_linker_version`].
    pub major_linker_version: u8,
    /// See docs for [`StandardFields::minor_linker_version`].
    pub minor_linker_version: u8,
    /// See docs for [`StandardFields::size_of_code`].
    pub size_of_code: u32,
    /// See docs for [`StandardFields::size_of_initialized_data`].
    pub size_of_initialized_data: u32,
    /// See docs for [`StandardFields::size_of_uninitialized_data`].
    pub size_of_uninitialized_data: u32,
    /// See docs for [`StandardFields::address_of_entry_point`].
    pub address_of_entry_point: u32,
    /// See docs for [`StandardFields::base_of_code`].
    pub base_of_code: u32,
    /// See docs for [`StandardFields::base_of_data`].
    pub base_of_data: u32,
}

pub const SIZEOF_STANDARD_FIELDS_32: usize = 28;

/// Standard 64-bit COFF fields (for `PE32+`).
///
/// In `winnt.h`, this is a subset of [`IMAGE_OPTIONAL_HEADER64`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64).
///
/// * For 32-bit version, see [`StandardFields32`].
/// * For unified version, see [`StandardFields`].
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct StandardFields64 {
    /// See docs for [`StandardFields::magic`](crate::pe::optional_header::StandardFields::magic).
    pub magic: u16,
    /// See docs for [`StandardFields::major_linker_version`].
    pub major_linker_version: u8,
    /// See docs for [`StandardFields::minor_linker_version`].
    pub minor_linker_version: u8,
    /// See docs for [`StandardFields::size_of_code`].
    pub size_of_code: u32,
    /// See docs for [`StandardFields::size_of_initialized_data`].
    pub size_of_initialized_data: u32,
    /// See docs for [`StandardFields::size_of_uninitialized_data`].
    pub size_of_uninitialized_data: u32,
    /// See docs for [`StandardFields::address_of_entry_point`].
    pub address_of_entry_point: u32,
    /// See docs for [`StandardFields::base_of_code`].
    pub base_of_code: u32,
}

pub const SIZEOF_STANDARD_FIELDS_64: usize = 24;

/// Unified 32/64-bit COFF fields (for `PE32` and `PE32+`).
///
/// Notably, a value of this type is a member of
/// [`goblin::pe::optional_header::OptionalHeader`](crate::pe::optional_header::OptionalHeader),
/// which represents either
/// * [`IMAGE_OPTIONAL_HEADER32`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32); or
/// * [`IMAGE_OPTIONAL_HEADER64`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64)
///
/// from `winnt.h`, depending on the value of [`StandardFields::magic`].
///
/// * For 32-bit version, see [`StandardFields32`].
/// * For 64-bit version, see [`StandardFields64`].
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct StandardFields {
    /// The state of the image file. This member can be one of the following values:
    ///
    /// * [`IMAGE_NT_OPTIONAL_HDR32_MAGIC`].
    /// * [`IMAGE_NT_OPTIONAL_HDR64_MAGIC`].
    /// * [`IMAGE_ROM_OPTIONAL_HDR_MAGIC`].
    #[doc(alias = "Magic")]
    pub magic: u16,
    /// The major version number of the linker.
    #[doc(alias = "MajorLinkerVersion")]
    pub major_linker_version: u8,
    /// The minor version number of the linker.
    #[doc(alias = "MinorLinkerVersion")]
    pub minor_linker_version: u8,
    /// The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections.
    #[doc(alias = "SizeOfCode")]
    pub size_of_code: u64,
    /// The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections.
    #[doc(alias = "SizeOfInitializedData")]
    pub size_of_initialized_data: u64,
    /// The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections.
    #[doc(alias = "SizeOfUninitializedData")]
    pub size_of_uninitialized_data: u64,
    /// A pointer to the entry point function, relative to the image base address.
    ///
    /// * For executable files, this is the starting address.
    /// * For device drivers, this is the address of the initialization function.
    ///
    /// The entry point function is optional for DLLs. When no entry point is present, this member is zero.
    pub address_of_entry_point: u64,
    /// A pointer to the beginning of the code section, relative to the image base.
    pub base_of_code: u64,
    /// A pointer to the beginning of the data section, relative to the image base. Absent in 64-bit PE32+
    // Q (JohnScience): Why is this a u32 and not an Option<u32>?
    pub base_of_data: u32,
}

impl From<StandardFields32> for StandardFields {
    fn from(fields: StandardFields32) -> Self {
        StandardFields {
            magic: fields.magic,
            major_linker_version: fields.major_linker_version,
            minor_linker_version: fields.minor_linker_version,
            size_of_code: u64::from(fields.size_of_code),
            size_of_initialized_data: u64::from(fields.size_of_initialized_data),
            size_of_uninitialized_data: u64::from(fields.size_of_uninitialized_data),
            address_of_entry_point: u64::from(fields.address_of_entry_point),
            base_of_code: u64::from(fields.base_of_code),
            base_of_data: fields.base_of_data,
        }
    }
}

impl From<StandardFields> for StandardFields32 {
    fn from(fields: StandardFields) -> Self {
        StandardFields32 {
            magic: fields.magic,
            major_linker_version: fields.major_linker_version,
            minor_linker_version: fields.minor_linker_version,
            size_of_code: fields.size_of_code as u32,
            size_of_initialized_data: fields.size_of_initialized_data as u32,
            size_of_uninitialized_data: fields.size_of_uninitialized_data as u32,
            address_of_entry_point: fields.address_of_entry_point as u32,
            base_of_code: fields.base_of_code as u32,
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
            size_of_code: u64::from(fields.size_of_code),
            size_of_initialized_data: u64::from(fields.size_of_initialized_data),
            size_of_uninitialized_data: u64::from(fields.size_of_uninitialized_data),
            address_of_entry_point: u64::from(fields.address_of_entry_point),
            base_of_code: u64::from(fields.base_of_code),
            base_of_data: 0,
        }
    }
}

impl From<StandardFields> for StandardFields64 {
    fn from(fields: StandardFields) -> Self {
        StandardFields64 {
            magic: fields.magic,
            major_linker_version: fields.major_linker_version,
            minor_linker_version: fields.minor_linker_version,
            size_of_code: fields.size_of_code as u32,
            size_of_initialized_data: fields.size_of_initialized_data as u32,
            size_of_uninitialized_data: fields.size_of_uninitialized_data as u32,
            address_of_entry_point: fields.address_of_entry_point as u32,
            base_of_code: fields.base_of_code as u32,
        }
    }
}

/// Standard fields magic number for 32-bit binary
pub const MAGIC_32: u16 = 0x10b;
/// Standard fields magic number for 64-bit binary
pub const MAGIC_64: u16 = 0x20b;

/// Windows specific fields
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct WindowsFields32 {
    pub image_base: u32,
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
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

pub const SIZEOF_WINDOWS_FIELDS_32: usize = 68;
/// Offset of the `check_sum` field in [`WindowsFields32`]
pub const OFFSET_WINDOWS_FIELDS_32_CHECKSUM: usize = 36;

/// 64-bit Windows specific fields
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct WindowsFields64 {
    pub image_base: u64,
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
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

pub const SIZEOF_WINDOWS_FIELDS_64: usize = 88;
/// Offset of the `check_sum` field in [`WindowsFields64`]
pub const OFFSET_WINDOWS_FIELDS_64_CHECKSUM: usize = 40;

// /// Generic 32/64-bit Windows specific fields
// #[derive(Debug, PartialEq, Copy, Clone, Default)]
// pub struct WindowsFields {
//     pub image_base: u64,
//     pub section_alignment: u32,
//     pub file_alignment: u32,
//     pub major_operating_system_version: u16,
//     pub minor_operating_system_version: u16,
//     pub major_image_version: u16,
//     pub minor_image_version: u16,
//     pub major_subsystem_version: u16,
//     pub minor_subsystem_version: u16,
//     pub win32_version_value: u32,
//     pub size_of_image: u32,
//     pub size_of_headers: u32,
//     pub check_sum: u32,
//     pub subsystem: u16,
//     pub dll_characteristics: u16,
//     pub size_of_stack_reserve: u64,
//     pub size_of_stack_commit:  u64,
//     pub size_of_heap_reserve:  u64,
//     pub size_of_heap_commit:   u64,
//     pub loader_flags: u32,
//     pub number_of_rva_and_sizes: u32,
// }

impl From<WindowsFields32> for WindowsFields {
    fn from(windows: WindowsFields32) -> Self {
        WindowsFields {
            image_base: u64::from(windows.image_base),
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
            size_of_stack_reserve: u64::from(windows.size_of_stack_reserve),
            size_of_stack_commit: u64::from(windows.size_of_stack_commit),
            size_of_heap_reserve: u64::from(windows.size_of_heap_reserve),
            size_of_heap_commit: u64::from(windows.size_of_heap_commit),
            loader_flags: windows.loader_flags,
            number_of_rva_and_sizes: windows.number_of_rva_and_sizes,
        }
    }
}

impl TryFrom<WindowsFields64> for WindowsFields32 {
    type Error = crate::error::Error;

    fn try_from(value: WindowsFields64) -> Result<Self, Self::Error> {
        Ok(WindowsFields32 {
            image_base: value.image_base.try_into()?,
            section_alignment: value.section_alignment,
            file_alignment: value.file_alignment,
            major_operating_system_version: value.major_operating_system_version,
            minor_operating_system_version: value.minor_operating_system_version,
            major_image_version: value.major_image_version,
            minor_image_version: value.minor_image_version,
            major_subsystem_version: value.major_subsystem_version,
            minor_subsystem_version: value.minor_subsystem_version,
            win32_version_value: value.win32_version_value,
            size_of_image: value.size_of_image,
            size_of_headers: value.size_of_headers,
            check_sum: value.check_sum,
            subsystem: value.subsystem,
            dll_characteristics: value.dll_characteristics,
            size_of_stack_reserve: value.size_of_stack_reserve.try_into()?,
            size_of_stack_commit: value.size_of_stack_commit.try_into()?,
            size_of_heap_reserve: value.size_of_heap_reserve.try_into()?,
            size_of_heap_commit: value.size_of_heap_commit.try_into()?,
            loader_flags: value.loader_flags,
            number_of_rva_and_sizes: value.number_of_rva_and_sizes,
        })
    }
}

// impl From<WindowsFields32> for WindowsFields {
//     fn from(windows: WindowsFields32) -> Self {
//         WindowsFields {
//             image_base: windows.image_base,
//             section_alignment: windows.section_alignment,
//             file_alignment: windows.file_alignment,
//             major_operating_system_version: windows.major_operating_system_version,
//             minor_operating_system_version: windows.minor_operating_system_version,
//             major_image_version: windows.major_image_version,
//             minor_image_version: windows.minor_image_version,
//             major_subsystem_version: windows.major_subsystem_version,
//             minor_subsystem_version: windows.minor_subsystem_version,
//             win32_version_value: windows.win32_version_value,
//             size_of_image: windows.size_of_image,
//             size_of_headers: windows.size_of_headers,
//             check_sum: windows.check_sum,
//             subsystem: windows.subsystem,
//             dll_characteristics: windows.dll_characteristics,
//             size_of_stack_reserve: windows.size_of_stack_reserve,
//             size_of_stack_commit: windows.size_of_stack_commit,
//             size_of_heap_reserve: windows.size_of_heap_reserve,
//             size_of_heap_commit: windows.size_of_heap_commit,
//             loader_flags: windows.loader_flags,
//             number_of_rva_and_sizes: windows.number_of_rva_and_sizes,
//         }
//     }
// }

pub type WindowsFields = WindowsFields64;

/// Either 32 or 64-bit optional header.
///
/// Whether it's 32 or 64-bit is determined by the [`StandardFields::magic`] and by the value
/// [`CoffHeader::size_of_optional_header`](crate::pe::header::CoffHeader::size_of_optional_header).
///
/// ## Position in PE binary
///
/// The optional header is located after [`CoffHeader`](crate::pe::header::CoffHeader) and before
/// section table.
#[derive(Debug, PartialEq, Copy, Clone)]
#[doc(alias = "IMAGE_OPTIONAL_HEADER32")]
#[doc(alias = "IMAGE_OPTIONAL_HEADER64")]
pub struct OptionalHeader {
    pub standard_fields: StandardFields,
    pub windows_fields: WindowsFields,
    pub data_directories: data_directories::DataDirectories,
}

/// Magic number for 32-bit binary (`PE32`).
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
/// Magic number for 64-bit binary (`PE32+`).
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
/// Magic number for a ROM image.
///
/// More info: <https://superuser.com/questions/156994/what-sort-of-program-has-its-pe-executable-header-set-to-rom-image>.
pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;

impl OptionalHeader {
    pub fn container(&self) -> error::Result<container::Container> {
        match self.standard_fields.magic {
            MAGIC_32 => Ok(container::Container::Little),
            MAGIC_64 => Ok(container::Container::Big),
            magic => Err(error::Error::BadMagic(u64::from(magic))),
        }
    }
}

impl<'a> ctx::TryFromCtx<'a, Endian> for OptionalHeader {
    type Error = crate::error::Error;
    fn try_from_ctx(bytes: &'a [u8], _: Endian) -> error::Result<(Self, usize)> {
        let magic = bytes.pread_with::<u16>(0, LE)?;
        let offset = &mut 0;
        let (standard_fields, windows_fields): (StandardFields, WindowsFields) = match magic {
            MAGIC_32 => {
                let standard_fields = bytes.gread_with::<StandardFields32>(offset, LE)?.into();
                let windows_fields = bytes.gread_with::<WindowsFields32>(offset, LE)?.into();
                (standard_fields, windows_fields)
            }
            MAGIC_64 => {
                let standard_fields = bytes.gread_with::<StandardFields64>(offset, LE)?.into();
                let windows_fields = bytes.gread_with::<WindowsFields64>(offset, LE)?;
                (standard_fields, windows_fields)
            }
            _ => return Err(error::Error::BadMagic(u64::from(magic))),
        };
        let data_directories = data_directories::DataDirectories::parse(
            &bytes,
            windows_fields.number_of_rva_and_sizes as usize,
            offset,
        )?;
        Ok((
            OptionalHeader {
                standard_fields,
                windows_fields,
                data_directories,
            },
            0,
        )) // TODO: FIXME
    }
}

impl ctx::TryIntoCtx<scroll::Endian> for OptionalHeader {
    type Error = error::Error;

    fn try_into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) -> Result<usize, Self::Error> {
        let offset = &mut 0;
        match self.standard_fields.magic {
            MAGIC_32 => {
                bytes.gwrite_with::<StandardFields32>(self.standard_fields.into(), offset, ctx)?;
                bytes.gwrite_with(WindowsFields32::try_from(self.windows_fields)?, offset, ctx)?;
                bytes.gwrite_with(self.data_directories, offset, ctx)?;
            }
            MAGIC_64 => {
                bytes.gwrite_with::<StandardFields64>(self.standard_fields.into(), offset, ctx)?;
                bytes.gwrite_with(self.windows_fields, offset, ctx)?;
                bytes.gwrite_with(self.data_directories, offset, ctx)?;
            }
            _ => panic!(),
        }
        Ok(*offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sizeof_standards32() {
        assert_eq!(
            ::std::mem::size_of::<StandardFields32>(),
            SIZEOF_STANDARD_FIELDS_32
        );
    }
    #[test]
    fn sizeof_windows32() {
        assert_eq!(
            ::std::mem::size_of::<WindowsFields32>(),
            SIZEOF_WINDOWS_FIELDS_32
        );
    }
    #[test]
    fn sizeof_standards64() {
        assert_eq!(
            ::std::mem::size_of::<StandardFields64>(),
            SIZEOF_STANDARD_FIELDS_64
        );
    }
    #[test]
    fn sizeof_windows64() {
        assert_eq!(
            ::std::mem::size_of::<WindowsFields64>(),
            SIZEOF_WINDOWS_FIELDS_64
        );
    }
}
