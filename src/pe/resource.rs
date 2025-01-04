use crate::error;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Not;
use log::debug;
use scroll::{Pread, Pwrite, SizeWith};

use crate::pe::data_directories;
use crate::pe::options;
use crate::pe::section_table;
use crate::pe::utils;

/// Size of `wchar_t` in C (aka [`u16`] in Rust)
pub(super) const SIZE_OF_WCHAR: usize = core::mem::size_of::<u16>();
/// Converts [`u8`] slice into a vector of [`u16`] and then utf-16 [`String`].
///
/// This function assumes that input bytes are multiple of `2`.
pub(super) fn to_utf16_string(bytes: &[u8]) -> String {
    let u16_slice = bytes
        .chunks(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&wchar| wchar != 0)
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&u16_slice)
}
/// Performs arbitrary alignment of values based on homogeneous numerical types.
#[inline]
pub(super) fn align_up<N>(value: N, align: N) -> N
where
    N: core::ops::Add<Output = N>
        + core::ops::Not<Output = N>
        + core::ops::BitAnd<Output = N>
        + core::ops::Sub<Output = N>
        + core::cmp::PartialEq
        + core::marker::Copy,
    u8: Into<N>,
{
    debug_assert!(align != 0u8.into(), "Align must be non-zero");
    (value + align - 1u8.into()) & !(align - 1u8.into())
}

/// Windows resource type identifier for cursors.
pub const RT_CURSOR: u16 = 1;
/// Windows resource type identifier for bitmaps.
pub const RT_BITMAP: u16 = 2;
/// Windows resource type identifier for icons.
pub const RT_ICON: u16 = 3;
/// Windows resource type identifier for menus.
pub const RT_MENU: u16 = 4;
/// Windows resource type identifier for dialog boxes.
pub const RT_DIALOG: u16 = 5;
/// Windows resource type identifier for string tables.
pub const RT_STRING: u16 = 6;
/// Windows resource type identifier for font directories.
pub const RT_FONTDIR: u16 = 7;
/// Windows resource type identifier for fonts.
pub const RT_FONT: u16 = 8;
/// Windows resource type identifier for accelerators.
pub const RT_ACCELERATOR: u16 = 9;
/// Windows resource type identifier for raw data.
pub const RT_RCDATA: u16 = 10;
/// Windows resource type identifier for message tables.
pub const RT_MESSAGETABLE: u16 = 11;
/// Windows resource type identifier for group cursors.
pub const RT_GROUP_CURSOR: u16 = 12;
/// Windows resource type identifier for group icons.
pub const RT_GROUP_ICON: u16 = 14;
/// Windows resource type identifier for version information.
pub const RT_VERSION: u16 = 16;
/// Windows resource type identifier for dialog includes.
pub const RT_DLGINCLUDE: u16 = 17;
/// Windows resource type identifier for Plug and Play resources.
pub const RT_PLUGPLAY: u16 = 19;
/// Windows resource type identifier for VxD resources.
pub const RT_VXD: u16 = 20;
/// Windows resource type identifier for animated cursors.
pub const RT_ANICURSOR: u16 = 21;
/// Windows resource type identifier for animated icons.
pub const RT_ANIICON: u16 = 22;
/// Windows resource type identifier for HTML resources.
pub const RT_HTML: u16 = 23;
/// Windows resource type identifier for manifests.
pub const RT_MANIFEST: u16 = 24;

/// Represents an image resource directory in the PE (Portable Executable) format.
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct ImageResourceDirectory {
    /// The characteristics of the resource directory.
    pub characteristics: u32,
    /// The timestamp of when the resource directory was created.
    pub time_date_stamp: u32,
    /// The major version of the resource directory.
    pub major_version: u16,
    /// The minor version of the resource directory.
    pub minor_version: u16,
    /// The number of named entries in the resource directory.
    pub number_of_named_entries: u16,
    /// The number of ID entries in the resource directory.
    pub number_of_id_entries: u16,
}

/// [`ResourceEntry::name_or_id`]: Indicates that the resource name is a string.
pub const IMAGE_RESOURCE_NAME_IS_STRING: u32 = 0x80000000;
/// [`ResourceEntry::offset_to_data_or_directory`]: Indicates that the resource data is a directory.
pub const IMAGE_RESOURCE_DATA_IS_DIRECTORY: u32 = 0x80000000;
/// A mask used to extract the union field from [`ResourceEntry`].
pub const IMAGE_RESOURCE_MASK: u32 = 0x7FFFFFFF;

impl<'a> ImageResourceDirectory {
    pub fn parse(
        bytes: &'a [u8],
        dd: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
    ) -> error::Result<Self> {
        Self::parse_with_opts(
            bytes,
            dd,
            sections,
            file_alignment,
            &options::ParseOptions::default(),
        )
    }

    pub fn parse_with_opts(
        bytes: &'a [u8],
        dd: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        opts: &options::ParseOptions,
    ) -> error::Result<Self> {
        let rva = dd.virtual_address as usize;
        let offset = utils::find_offset(rva, sections, file_alignment, opts).ok_or_else(|| {
            error::Error::Malformed(format!(
                "Cannot map ImageResourceDirectory rva {:#x} into offset",
                rva
            ))
        })?;
        let resource_dir = bytes.pread_with(offset, scroll::LE)?;
        Ok(resource_dir)
    }

    /// Counts the total number of resource entries (both named and ID entries).
    ///
    /// Returns the sum of [`ImageResourceDirectory::number_of_id_entries`] and [`ImageResourceDirectory::number_of_named_entries`]
    /// from the [`ImageResourceDirectory`].
    pub fn count(&self) -> u16 {
        self.number_of_id_entries + self.number_of_named_entries
    }

    /// Returns the total size of entries in bytes
    pub fn entries_size(&self) -> usize {
        self.count() as usize * RESOURCE_ENTRY_SIZE
    }

    /// Returns the next resource entry iterator
    pub fn next_iter(&self, offset: usize, bytes: &'a [u8]) -> ResourceEntryIterator<'a> {
        ResourceEntryIterator {
            num_resources: self.count() as usize,
            data: &bytes[offset..offset + self.entries_size()],
        }
    }
}

/// Iterator over [`ResourceData`]
#[derive(Debug, Copy, Clone)]
pub struct ResourceEntryIterator<'a> {
    /// Total number of ID entries and named entries
    ///
    /// Must be equals to [`ImageResourceDirectory::number_of_named_entries`] + [`ImageResourceDirectory::number_of_id_entries`]
    num_resources: usize,
    /// Raw data of resource direcrory without [`ImageResourceDirectory`] and scoped to [`RESOURCE_ENTRY_SIZE`] * [`Self::num_resources`]
    data: &'a [u8],
}

impl Iterator for ResourceEntryIterator<'_> {
    type Item = error::Result<ResourceEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        Some(match self.data.pread_with(0, scroll::LE) {
            Ok(func) => {
                self.data = &self.data[RESOURCE_ENTRY_SIZE..];
                Ok(func)
            }
            Err(error) => {
                self.data = &[];
                Err(error.into())
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.data.len() / RESOURCE_ENTRY_SIZE;
        (len, Some(len))
    }
}

impl<'a> ResourceEntryIterator<'a> {
    /// Find the resource entry by its resource ID.
    pub fn find_by_id(&self, id: u16) -> error::Result<Option<ResourceEntry>> {
        self.map(|x| {
            x.and_then(|x| {
                if x.id() == Some(id) {
                    Ok(Some(x))
                } else {
                    Ok(None)
                }
            })
        })
        .find_map(Result::transpose)
        .transpose()
    }
}

/// Represents an entry in a resource data entry structure.
///
/// This struct contains information about a specific resource, including
/// the offset to the resource data, the size of the resource, the code page,
/// and any reserved fields for future use.
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct ResourceDataEntry {
    /// The offset from the beginning of the resource data directory to the actual
    /// resource data in memory.
    ///
    /// The name of this field is confusing, but this is really a RVA.
    pub offset_to_data: u32,
    /// The size of the resource data in bytes.
    pub size: u32,
    /// The code page used for the resource data, which specifies the character
    /// encoding for strings within the resource.
    pub code_page: u32,
    /// Reserved field for future use.
    pub reserved: u32,
}

/// Represents a resource entry in the PE (Portable Executable) format.
#[repr(C)]
#[derive(PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct ResourceEntry {
    /// The name or identifier of the resource entry.
    pub name_or_id: u32,
    /// The offset to the resource data or directory.
    pub offset_to_data_or_directory: u32,
}

/// Size of [`ResourceEntry`]
pub const RESOURCE_ENTRY_SIZE: usize = core::mem::size_of::<u64>();

impl fmt::Debug for ResourceEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ResourceEntry")
            .field("value", &format_args!("{:#x}", self.value()))
            .field("name_is_string", &self.name_is_string())
            .field("name_offset", &format_args!("{:#x}", self.name_offset()))
            .field("id", &self.id())
            .field("data_is_directory", &self.data_is_directory())
            .field(
                "offset_to_directory",
                &format_args!("{:#x}", self.offset_to_directory()),
            )
            .field(
                "offset_to_data",
                &format_args!("{:#x?}", self.offset_to_data()),
            )
            .finish()
    }
}

impl ResourceEntry {
    /// Reinterprets the struct as [`u64`]
    pub fn value(&self) -> u64 {
        ((self.name_or_id) as u64) << 32 | self.offset_to_data_or_directory as u64
    }

    /// Checks if the resource name is a string.
    ///
    /// Returns `true` if the name is a string, otherwise `false`.
    pub fn name_is_string(&self) -> bool {
        self.name_or_id & IMAGE_RESOURCE_NAME_IS_STRING != 0
    }

    /// Retrieves the offset of the resource name or ID.
    ///
    /// If the name is a string, it returns the offset to the string.
    /// If it is an ID, it returns the ID masked to remove the string flag.
    pub fn name_offset(&self) -> u32 {
        self.name_or_id & IMAGE_RESOURCE_MASK
    }

    /// Retrieves the ID of the resource if the name is not a string.
    ///
    /// Returns `Some(u16)` if the name is an ID, otherwise `None`.
    ///
    /// One of:
    /// - [`RT_CURSOR`]
    /// - [`RT_BITMAP`]
    /// - [`RT_ICON`]
    /// - [`RT_MENU`]
    /// - [`RT_DIALOG`]
    /// - [`RT_STRING`]
    /// - [`RT_FONTDIR`]
    /// - [`RT_FONT`]
    /// - [`RT_ACCELERATOR`]
    /// - [`RT_RCDATA`]
    /// - [`RT_MESSAGETABLE`]
    /// - [`RT_GROUP_CURSOR`]
    /// - [`RT_GROUP_ICON`]
    /// - [`RT_VERSION`]
    /// - [`RT_DLGINCLUDE`]
    /// - [`RT_PLUGPLAY`]
    /// - [`RT_VXD`]
    /// - [`RT_ANICURSOR`]
    /// - [`RT_ANIICON`]
    /// - [`RT_HTML`]
    /// - [`RT_MANIFEST`]
    pub fn id(&self) -> Option<u16> {
        self.name_is_string().not().then(|| self.name_or_id as u16)
    }

    /// Checks if the resource entry points to a directory.
    ///
    /// Returns `true` if the resource data is a directory, otherwise `false`.
    pub fn data_is_directory(&self) -> bool {
        self.offset_to_data_or_directory & IMAGE_RESOURCE_DATA_IS_DIRECTORY != 0
    }

    /// Retrieves the offset to the resource directory.
    ///
    /// If the resource entry points to a directory, it returns the offset masked to remove the directory flag.
    pub fn offset_to_directory(&self) -> u32 {
        self.offset_to_data_or_directory & IMAGE_RESOURCE_MASK
    }

    /// Retrieves the offset to the resource data if the entry does not point to a directory.
    ///
    /// Returns `Some(u32)` if the resource entry points to data, otherwise `None`.
    pub fn offset_to_data(&self) -> Option<u32> {
        self.data_is_directory()
            .not()
            .then(|| self.offset_to_data_or_directory)
    }

    /// Returns the next depth entry of [`ResourceEntry`] if present
    pub fn next_depth<'a>(&self, bytes: &'a [u8]) -> error::Result<Option<ResourceEntry>> {
        let mut offset = self.offset_to_directory() as usize;

        let dir = bytes.gread_with::<ImageResourceDirectory>(&mut offset, scroll::LE)?;
        let iterator = dir.next_iter(offset, bytes);
        let entries = iterator.collect::<Result<Vec<_>, _>>()?;

        Ok(entries.first().map(|x| *x))
    }

    /// Returns next depth entry of [`ResourceEntry`] recursively while either `predicate` returns `true` or reach the final depth
    pub fn recursive_next_depth<'a, P>(
        &self,
        bytes: &'a [u8],
        predicate: P,
    ) -> error::Result<Option<ResourceEntry>>
    where
        P: Fn(&Self) -> bool,
    {
        if let Some(next) = self.next_depth(bytes)? {
            if !predicate(&next) {
                Ok(Some(next))
            } else {
                next.recursive_next_depth(bytes, predicate)
            }
        } else {
            Ok(Some(*self))
        }
    }
}

impl From<u64> for ResourceEntry {
    fn from(value: u64) -> Self {
        Self {
            name_or_id: (value >> 32) as u32,
            offset_to_data_or_directory: value as u32,
        }
    }
}

/// Represents the resource data associated with a PE (Portable Executable) image.
#[derive(Debug, Copy, Clone, Default)]
pub struct ResourceData<'a> {
    /// The image resource directory containing metadata about the resources.
    pub image_resource_directory: ImageResourceDirectory,
    /// The raw data of the resources.
    data: &'a [u8],
    /// Version information if present
    pub version_info: Option<VersionInfo<'a>>,
    /// Manifest data if present
    pub manifest_data: Option<ManifestData<'a>>,
}

impl<'a> ResourceData<'a> {
    pub fn parse(
        bytes: &'a [u8],
        dd: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
    ) -> error::Result<Self> {
        Self::parse_with_opts(
            bytes,
            dd,
            sections,
            file_alignment,
            &options::ParseOptions::default(),
        )
    }

    pub fn parse_with_opts(
        bytes: &'a [u8],
        dd: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        opts: &options::ParseOptions,
    ) -> error::Result<Self> {
        let image_resource_directory =
            ImageResourceDirectory::parse_with_opts(bytes, dd, sections, file_alignment, opts)?;

        let rva = dd.virtual_address as usize;
        let offset = utils::find_offset(rva, sections, file_alignment, opts).ok_or_else(|| {
            error::Error::Malformed(format!(
                "Cannot map ImageResourceDirectory rva {:#x} into offset",
                rva
            ))
        })?;

        if offset + dd.size as usize > bytes.len() {
            return Err(error::Error::Malformed(format!(
                "Resource directory offset ({:#x}) and size ({:#x}) exceeds bytes slice ({:#x})",
                offset,
                dd.size,
                bytes.len()
            )));
        }
        let data = &bytes[offset..offset + dd.size as usize];

        let count = image_resource_directory.count() as usize;
        let offset = core::mem::size_of::<ImageResourceDirectory>();
        let size = image_resource_directory.entries_size();
        if offset + size as usize > data.len() {
            return Err(error::Error::Malformed(format!(
                "Resource entry offset ({:#x}) and size ({:#x}) exceeds data slice ({:#x})",
                offset,
                size,
                data.len()
            )));
        }
        let iterator_data = &data[offset..offset + size];
        let iterator = ResourceEntryIterator {
            num_resources: count,
            data: iterator_data,
        };
        let version_info =
            VersionInfo::parse(bytes, data, iterator, sections, file_alignment, opts)?;
        let manifest_data =
            ManifestData::parse(bytes, data, iterator, sections, file_alignment, opts)?;

        Ok(ResourceData {
            image_resource_directory,
            data,
            version_info,
            manifest_data,
        })
    }

    /// Counts the total number of resource entries (both named and ID entries).
    ///
    /// Returns the sum of [`ImageResourceDirectory::number_of_id_entries`] and [`ImageResourceDirectory::number_of_named_entries`]
    /// from the [`Self::image_resource_directory`].
    pub fn count(&self) -> u16 {
        self.image_resource_directory.count()
    }

    /// Creates an iterator over the [`ResourceEntry`].
    ///
    /// Returns a [`ResourceEntryIterator`] that can be used to iterate over
    /// the resource entries contained within this resource data.
    pub fn entries(&self) -> ResourceEntryIterator<'a> {
        let offset = core::mem::size_of::<ImageResourceDirectory>();
        let size = self.image_resource_directory.entries_size();
        // Safety: Panic-free is guaranteed here by Self::parse_with_opts
        ResourceEntryIterator {
            num_resources: self.count() as usize,
            data: &self.data[offset..offset + size],
        }
    }
}

/// [`VsFixedFileInfo::signature`]: The signature for the fixed file information structure in the version resource.
pub const VS_FFI_SIGNATURE: u32 = 0xFEEF04BD;
/// [`VsFixedFileInfo::struct_version`]: The structure version for the fixed file information.
///
/// NOTE: Typo is inherited from Windows SDK (perhaps typo by Microsoft employee).
pub const VS_FFI_STRUCVERSION: u32 = 0x00010000;
/// [`VsFixedFileInfo::file_flags_mask`]: A mask to extract the file flags from the fixed file information.
pub const VS_FFI_FILEFLAGSMASK: u32 = 0x0000003F;

/// [`VsFixedFileInfo::file_flags`]: Indicates that the file is a debug build.
pub const VS_FF_DEBUG: u32 = 0x00000001;
/// [`VsFixedFileInfo::file_flags`]: Indicates that the file is a pre-release version.
pub const VS_FF_PRERELEASE: u32 = 0x00000002;
/// [`VsFixedFileInfo::file_flags`]: Indicates that the file has been patched.
pub const VS_FF_PATCHED: u32 = 0x00000004;
/// [`VsFixedFileInfo::file_flags`]: Indicates that the file is a private build.
pub const VS_FF_PRIVATEBUILD: u32 = 0x00000008;
/// [`VsFixedFileInfo::file_flags`]: Indicates that information about the file is inferred.
pub const VS_FF_INFOINFERRED: u32 = 0x00000010;
/// [`VsFixedFileInfo::file_flags`]: Indicates that the file is a special build.
pub const VS_FF_SPECIALBUILD: u32 = 0x00000020;

// VS_VERSION.dwFileFlags

/// [`VsFixedFileInfo::file_os`]: Indicates an unknown operating system.
pub const VOS_UNKNOWN: u32 = 0x00000000;
/// [`VsFixedFileInfo::file_os`]: Indicates the DOS operating system.
pub const VOS_DOS: u32 = 0x00010000;
/// [`VsFixedFileInfo::file_os`]: Indicates OS/2 version 1.6 (16-bit).
pub const VOS_OS216: u32 = 0x00020000;
/// [`VsFixedFileInfo::file_os`]: Indicates OS/2 version 2.0 (32-bit).
pub const VOS_OS232: u32 = 0x00030000;
/// [`VsFixedFileInfo::file_os`]: Indicates the Windows NT operating system.
pub const VOS_NT: u32 = 0x00040000;
/// [`VsFixedFileInfo::file_os`]: Indicates the Windows CE operating system.
pub const VOS_WINCE: u32 = 0x00050000;

// VS_VERSION.dwFileFlags

/// [`VsFixedFileInfo::file_flags`]: Indicates the base operating system type.
#[doc(alias("VOS__BASE"))]
pub const VOS_BASE: u32 = 0x00000000;
/// [`VsFixedFileInfo::file_flags`]: Indicates the Windows 16-bit operating system.
#[doc(alias("VOS__WINDOWS16"))]
pub const VOS_WINDOWS16: u32 = 0x00000001;
/// [`VsFixedFileInfo::file_flags`]: Indicates the Presentation Manager (PM) 16-bit operating system.
#[doc(alias("VOS__PM16"))]
pub const VOS_PM16: u32 = 0x00000002;
/// [`VsFixedFileInfo::file_flags`]: Indicates the Presentation Manager (PM) 32-bit operating system.
#[doc(alias("VOS__PM32"))]
pub const VOS_PM32: u32 = 0x00000003;
/// [`VsFixedFileInfo::file_flags`]: Indicates the Windows 32-bit operating system.
#[doc(alias("VOS__WINDOWS32"))]
pub const VOS_WINDOWS32: u32 = 0x00000004;

// VS_VERSION.dwFileOS

/// [`VsFixedFileInfo::file_os`]: Indicates DOS with Windows 16-bit compatibility.
pub const VOS_DOS_WINDOWS16: u32 = 0x00010001;
/// [`VsFixedFileInfo::file_os`]: Indicates DOS with Windows 32-bit compatibility.
pub const VOS_DOS_WINDOWS32: u32 = 0x00010004;
/// [`VsFixedFileInfo::file_os`]: Indicates OS/2 1.6 with Presentation Manager 16-bit.
pub const VOS_OS216_PM16: u32 = 0x00020002;
/// [`VsFixedFileInfo::file_os`]: Indicates OS/2 1.6 with Presentation Manager 32-bit.
pub const VOS_OS216_PM32: u32 = 0x00030003;
/// [`VsFixedFileInfo::file_os`]: Indicates Windows NT with Windows 32-bit compatibility.
pub const VOS_NT_WINDOWS32: u32 = 0x00040004;

// VS_VERSION.dwFileType

/// [`VsFixedFileInfo::file_type`]: Indicates an unknown file type.
pub const VFT_UNKNOWN: u32 = 0x00000000;
/// [`VsFixedFileInfo::file_type`]: Indicates an application file type.
pub const VFT_APP: u32 = 0x00000001;
/// [`VsFixedFileInfo::file_type`]: Indicates a dynamic link library (DLL) file type.
pub const VFT_DLL: u32 = 0x00000002;
/// [`VsFixedFileInfo::file_type`]: Indicates a device driver file type.
pub const VFT_DRV: u32 = 0x00000003;
/// [`VsFixedFileInfo::file_type`]: Indicates a font file type.
pub const VFT_FONT: u32 = 0x00000004;
/// [`VsFixedFileInfo::file_type`]: Indicates a virtual device driver (VXD) file type.
pub const VFT_VXD: u32 = 0x00000005;
/// [`VsFixedFileInfo::file_type`]: Indicates a static library file type.
pub const VFT_STATIC_LIB: u32 = 0x00000007;

// VS_VERSION.dwFileSubtype for VFT_WINDOWS_DRV

/// [`VsFixedFileInfo::file_subtype`]: Indicates an unknown driver subtype.
pub const VFT2_UNKNOWN: u32 = 0x00000000;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a printer driver subtype.
pub const VFT2_DRV_PRINTER: u32 = 0x00000001;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a keyboard driver subtype.
pub const VFT2_DRV_KEYBOARD: u32 = 0x00000002;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a language driver subtype.
pub const VFT2_DRV_LANGUAGE: u32 = 0x00000003;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a display driver subtype.
pub const VFT2_DRV_DISPLAY: u32 = 0x00000004;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a mouse driver subtype.
pub const VFT2_DRV_MOUSE: u32 = 0x00000005;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a network driver subtype.
pub const VFT2_DRV_NETWORK: u32 = 0x00000006;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a system driver subtype.
pub const VFT2_DRV_SYSTEM: u32 = 0x00000007;
/// [`VsFixedFileInfo::file_subtype`]: Indicates an installable driver subtype.
pub const VFT2_DRV_INSTALLABLE: u32 = 0x00000008;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a sound driver subtype.
pub const VFT2_DRV_SOUND: u32 = 0x00000009;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a communication driver subtype.
pub const VFT2_DRV_COMM: u32 = 0x0000000A;
/// [`VsFixedFileInfo::file_subtype`]: Indicates an input method driver subtype.
pub const VFT2_DRV_INPUTMETHOD: u32 = 0x0000000B;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a versioned printer driver subtype.
pub const VFT2_DRV_VERSIONED_PRINTER: u32 = 0x0000000C;

// VS_VERSION.dwFileSubtype for VFT_WINDOWS_FONT

/// [`VsFixedFileInfo::file_subtype`]: Indicates a raster font subtype.
pub const VFT2_FONT_RASTER: u32 = 0x00000001;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a vector font subtype.
pub const VFT2_FONT_VECTOR: u32 = 0x00000002;
/// [`VsFixedFileInfo::file_subtype`]: Indicates a TrueType font subtype.
pub const VFT2_FONT_TRUETYPE: u32 = 0x00000003;

/// Iterator over [`ResourceString`]
#[derive(Debug, Copy, Clone)]
pub struct ResourceStringIterator<'a> {
    /// The raw data must be scoped to the [`ResourceDataEntry`]
    pub data: &'a [u8],
}

impl<'a> Iterator for ResourceStringIterator<'a> {
    type Item = error::Result<ResourceString<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let mut offset = 0;
        Some(match ResourceString::parse(self.data, &mut offset) {
            Ok(next) => {
                debug!(
                    "Parsed next resource string as size {:#x}: {:#x?}",
                    offset, next?
                );
                self.data = &self.data[offset..];
                Ok(next?)
            }
            Err(error) => {
                self.data = &[];
                Err(error.into())
            }
        })
    }
}

/// Represents a resource string entry.
#[derive(Copy, Clone, PartialEq)]
pub struct ResourceString<'a> {
    /// The length, in bytes, of this [`ResourceString`] structure.
    pub len: u16,
    /// The size, in words, of the [`ResourceString::value`].
    ///
    /// - When [`ResourceString::type`] indicates string data: multiply this field with [`SIZE_OF_WCHAR`] that should be the actual size of [`ResourceString::value`] with null-terminator.
    /// - Othereise, treat as-is.
    pub value_len: u16,
    /// The type of [`ResourceString::value`] in the version resource.
    ///
    /// This member is `1` if the version resource contains text data;
    /// and `0` if the version resource contains binary data, otherwise sometimes an invalid value.
    pub r#type: u16,
    /// An arbitrary null-terminated utf-16 unicode string.
    pub key: &'a [u8],
    /// An arbitrary null-terminated utf-16 unicode string or binary data depends on [`ResourceString::type`].
    pub value: &'a [u8],
}

/// Fields in [`ResourceString`] must be aligned with size of [`u32`] while parsing
pub const RESOURCE_STRING_FIELD_ALIGNMENT: usize = core::mem::size_of::<u32>();

impl fmt::Debug for ResourceString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_struct = f.debug_struct("ResourceString");

        debug_struct.field("len", &format_args!("{:#x}", self.len));

        if self.is_text_data() {
            // If this is string data, acrual size is multiple of 2 (sizeof wchar_t)
            debug_struct.field(
                "value_len",
                &format_args!(
                    "{:#x} ({} bytes)",
                    self.value_len,
                    self.value_len * SIZE_OF_WCHAR as u16
                ),
            );
        } else {
            debug_struct.field("value_len", &format_args!("{:#x}", self.value_len));
        }

        debug_struct
            .field(
                "type",
                &format_args!(
                    "{} ({})",
                    self.r#type,
                    match self.r#type {
                        0 => "Binary Data",
                        1 => "String Data",
                        _ => "Unknown",
                    }
                ),
            )
            .field("key", &self.key_string())
            .field(
                "key_slice",
                &format_args!("{:02x?} ({} bytes)", self.key, self.key.len()),
            );

        if self.is_text_data() && self.value_len > 0 {
            debug_struct.field("value", &self.value_string());
        }

        debug_struct
            .field(
                "value_slice",
                &format_args!(
                    "{:02x?} ({} bytes, {})",
                    self.value,
                    self.value.len(),
                    if self.value.len() == self.value_len as usize {
                        "Correct"
                    } else {
                        "Incorrect"
                    }
                ),
            )
            .finish()
    }
}

impl<'a> ResourceString<'a> {
    pub fn parse(bytes: &'a [u8], offset: &mut usize) -> error::Result<Option<Self>> {
        let len = bytes.gread_with::<u16>(offset, scroll::LE)?;
        if len == 0 {
            return Ok(None);
        }
        let value_len = bytes.gread_with::<u16>(offset, scroll::LE)?;
        let r#type = bytes.gread_with::<u16>(offset, scroll::LE)?;
        *offset = align_up(*offset, RESOURCE_STRING_FIELD_ALIGNMENT);
        let key_size = &bytes[*offset..]
            .chunks(2)
            .take_while(|x| u16::from_le_bytes([x[0], x[1]]) != 0u16)
            .count()
            * SIZE_OF_WCHAR;
        if (*offset - SIZE_OF_WCHAR) + key_size + SIZE_OF_WCHAR > bytes.len() {
            return Err(error::Error::Malformed(format!(
                "offset ({:#x}) and key_size ({:#x}) is greater than bytes len {:#x}",
                offset,
                key_size,
                bytes.len()
            )));
        }
        let key =
            &bytes[*offset - SIZE_OF_WCHAR..*offset - SIZE_OF_WCHAR + key_size + SIZE_OF_WCHAR];
        *offset += align_up(key.len(), RESOURCE_STRING_FIELD_ALIGNMENT);
        let real_value_len = align_up(
            if r#type == 1 {
                value_len as usize * SIZE_OF_WCHAR
            } else {
                value_len as usize
            },
            4,
        );
        if *offset + (real_value_len as usize) > bytes.len() {
            return Err(error::Error::Malformed(format!(
                "offset ({:#x}) and real_value_len ({:#x}) is greater than bytes len {:#x}",
                offset,
                real_value_len,
                bytes.len()
            )));
        }
        let value = &bytes[*offset..*offset + real_value_len as usize];
        *offset += value.len();
        Ok(Some(Self {
            len,
            value_len,
            r#type,
            key,
            value,
        }))
    }

    /// Returns `true` if [`ResourceString::value`] is expected to an null-terminated unicode string
    pub fn is_text_data(&self) -> bool {
        self.r#type == 1
    }

    /// Returns `true` if [`ResourceString::value`] is expected to a binary data
    pub fn is_binary_data(&self) -> bool {
        self.r#type == 0
    }

    /// Converts [`ResourceString::key`] into a [`String`]
    pub fn key_string(&self) -> String {
        to_utf16_string(&self.key)
    }

    /// Converts [`ResourceString::value`] into a [`String`]
    pub fn value_string(&self) -> String {
        to_utf16_string(&self.value)
    }
}

/// Represents a generic version format, commonly used for file or product versioning within Windows SDK.
///
/// The version information is stored in four parts:
/// - `major`: The major version, typically indicating significant updates or changes.
/// - `minor`: The minor version, for less impactful updates or feature additions.
/// - `build`: The build number, often used for tracking internal builds or revisions.
/// - `revision`: The revision number, generally indicating small fixes or patches.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Default)]
pub struct VersionField {
    /// The major version, indicating significant updates or releases.
    pub major: u16,
    /// The minor version, indicating smaller feature additions or changes.
    pub minor: u16,
    /// The build number, often used to distinguish between internal builds.
    pub build: u16,
    /// The revision number, typically used for small fixes or patches.
    pub revision: u16,
}

impl VersionField {
    /// Creates a new [`VersionField`] from the combination of [`u32`] fields.
    ///
    /// # Parameters
    /// - `ms`: The [`u32`] representation of a most significant part, which contains the major and minor version.
    /// - `ls`: The [`u32`] representation of a least significant part, which contains the build and revision.
    pub fn from_ms_ls(ms: u32, ls: u32) -> Self {
        let major = (ms >> 16) as u16;
        let minor = (ms & 0xFFFF) as u16;
        let build = (ls >> 16) as u16;
        let revision = (ls & 0xFFFF) as u16;
        Self {
            major,
            minor,
            build,
            revision,
        }
    }

    /// Converts [`VersionField`] back to the [`u32`] most significant field.
    ///
    /// - Upper 16-bits: Major version (`HIWORD`)
    /// - Lower 16-bits: Minor version (`LOWORD`)
    pub fn to_ms(&self) -> u32 {
        ((self.major as u32) << 16) | (self.minor as u32)
    }

    /// Converts [`VersionField`] back to the [`u32`] least significant field.
    ///
    /// - Upper 16-bits: Build number (`HIWORD`)
    /// - Lower 16-bits: Revision number (`LOWORD`)
    pub fn to_ls(&self) -> u32 {
        ((self.build as u32) << 16) | (self.revision as u32)
    }

    /// Formats the version as a [`String`] in the format "major.minor.build.revision".
    pub fn to_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

/// Represents the fixed file information structure used in the version resource
/// of a Portable Executable (PE) file.
#[repr(C)]
#[derive(PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct VsFixedFileInfo {
    /// The signature of the fixed file information structure. Must be equals to [`VS_FFI_SIGNATURE`].
    pub signature: u32,
    /// The version of the structure.
    pub struct_version: u32,
    /// The file version (most significant part).
    pub file_version_ms: u32,
    /// The file version (least significant part).
    pub file_version_ls: u32,
    /// The product version (most significant part).
    pub product_version_ms: u32,
    /// The product version (least significant part).
    pub product_version_ls: u32,
    /// The mask for the file flags.
    pub file_flags_mask: u32,
    /// The file flags that specify characteristics of the file.
    pub file_flags: u32,
    /// The operating system that the file is designed for.
    pub file_os: u32,
    /// The type of the file (e.g., executable, DLL).
    pub file_type: u32,
    /// The subtype of the file (specific to the file type).
    pub file_subtype: u32,
    /// The file date (most significant part).
    pub file_date_ms: u32,
    /// The file date (least significant part).
    pub file_date_ls: u32,
}

impl fmt::Debug for VsFixedFileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VsFixedFileInfo")
            .field(
                "signature",
                &format_args!(
                    "{:#x} ({})",
                    &self.signature,
                    if self.is_valid() { "Valid" } else { "Invalid" }
                ),
            )
            .field(
                "struct_version",
                &format_args!("{:#x}", &self.struct_version),
            )
            .field(
                "file_version_ms",
                &format_args!("{:#x}", &self.file_version_ms),
            )
            .field(
                "file_version_ls",
                &format_args!("{:#x}", &self.file_version_ls),
            )
            .field(
                "product_version_ms",
                &format_args!("{:#x}", &self.product_version_ms),
            )
            .field(
                "product_version_ls",
                &format_args!("{:#x}", &self.product_version_ls),
            )
            .field(
                "file_flags_mask",
                &format_args!("{:#x}", &self.file_flags_mask),
            )
            .field("file_flags", &format_args!("{:#x}", &self.file_flags))
            .field("file_os", &format_args!("{:#x}", &self.file_os))
            .field("file_type", &format_args!("{:#x}", &self.file_type))
            .field("file_subtype", &format_args!("{:#x}", &self.file_subtype))
            .field("file_date_ms", &format_args!("{:#x}", &self.file_date_ms))
            .field("file_date_ls", &format_args!("{:#x}", &self.file_date_ls))
            .finish()
    }
}

/// Language and codepage identifier for U.S. English with Unicode (UTF-16) in Windows SDK version info.
///
/// This identifier consists of the following components:
/// - `04`: Primary language identifier for English.
/// - `09`: Sub-language identifier for United States.
/// - `04E4`: Codepage identifier for Unicode (UTF-16).
///
/// This value may present in [`ResourceString::key`] without no dedicated value data.
pub const VERSION_INFO_US_ENGLISH_UNICODE: &str = "040904E4";
/// A [`ResourceString::key`] of [`VsFixedFileInfo`]
pub const VS_VERSION_INFO_KEY: &str = "VS_VERSION_INFO";

impl VsFixedFileInfo {
    /// Returns `true` if [`Self::signature`] equals to [`VS_FFI_SIGNATURE`], otherwise `false`.
    pub fn is_valid(&self) -> bool {
        self.signature == VS_FFI_SIGNATURE
    }

    /// Reinterprets [`VsFixedFileInfo::file_version_ms`] and [`VsFixedFileInfo::file_version_ls`] into a generic [`VersionField`].
    pub fn file_version(&self) -> VersionField {
        VersionField::from_ms_ls(self.file_date_ms, self.file_date_ls)
    }

    /// Reinterprets [`VsFixedFileInfo::product_version_ms`] and [`VsFixedFileInfo::product_version_ls`] into a generic [`VersionField`].
    pub fn product_version(&self) -> VersionField {
        VersionField::from_ms_ls(self.product_version_ms, self.product_version_ls)
    }
}

/// Represents a collection of string-based file information in a version resource.
///
/// This struct holds various metadata attributes about a file, such as the company name,
/// file description, version information, and copyright details. Each field is optional and
/// can be absent if the information is not available.
#[derive(Copy, Clone)]
pub struct StringFileInfo<'a> {
    /// Additional information for diagnostic purposes. Can be of arbitrary length.
    pub comments: Option<&'a [u8]>,
    /// The name of the company that produced the file, e.g., "Microsoft Corporation".
    pub company_name: Option<&'a [u8]>,
    /// A description of the file suitable for presentation to users, e.g., "Keyboard driver for AT-style keyboards".
    pub file_description: Option<&'a [u8]>,
    /// The version of the file, e.g., "3.00A" or "5.00.RC2".
    pub file_version: Option<&'a [u8]>,
    /// The internal name of the file, which may include module names for DLLs or device names.
    pub internal_name: Option<&'a [u8]>,
    /// Copyright notices and trademarks related to the file, formatted as "Copyright Microsoft Corp. 1990 1994".
    pub legal_copyright: Option<&'a [u8]>,
    /// Trademarks and registered trademarks associated with the file, e.g., "Windows is a trademark of Microsoft Corporation".
    pub legal_trademarks: Option<&'a [u8]>,
    /// The original name of the file (without a path), used to determine if it has been renamed.
    pub original_filename: Option<&'a [u8]>,
    /// Information about who, where, and why the private version of the file was built,
    /// applicable only if the [`VS_FF_PRIVATEBUILD`] flag is set.
    pub private_build: Option<&'a [u8]>,
    /// The name of the product with which this file is distributed, e.g., "Microsoft Windows".
    pub product_name: Option<&'a [u8]>,
    /// The version of the product associated with this file, e.g., "3.00A" or "5.00.RC2".
    pub product_version: Option<&'a [u8]>,
    /// A description of how this version differs from the normal version, applicable only if the
    /// [`VS_FF_SPECIALBUILD`] flag is set.
    pub special_build: Option<&'a [u8]>,
}

impl fmt::Debug for StringFileInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("StringFileInfo")
            .field("comments", &format_args!("{:?}", self.comments()))
            .field("company_name", &format_args!("{:?}", self.company_name()))
            .field(
                "file_description",
                &format_args!("{:?}", self.file_description()),
            )
            .field("file_version", &format_args!("{:?}", self.file_version()))
            .field("internal_name", &format_args!("{:?}", self.internal_name()))
            .field(
                "legal_copyright",
                &format_args!("{:?}", self.legal_copyright()),
            )
            .field(
                "legal_trademarks",
                &format_args!("{:?}", self.legal_trademarks()),
            )
            .field(
                "original_filename",
                &format_args!("{:?}", self.original_filename()),
            )
            .field("private_build", &format_args!("{:?}", self.private_build()))
            .field("product_name", &format_args!("{:?}", self.product_name()))
            .field(
                "product_version",
                &format_args!("{:?}", self.product_version()),
            )
            .field("special_build", &format_args!("{:?}", self.special_build()))
            .finish()
    }
}

impl<'a> StringFileInfo<'a> {
    fn from_resource_string_iterator(it: ResourceStringIterator<'a>) -> Self {
        let find = |s| {
            it.filter_map(Result::ok)
                .find(|x| x.key_string() == s)
                .and_then(|x| Some(x.value))
        };

        Self {
            comments: find("Comments"),
            company_name: find("CompanyName"),
            file_description: find("FileDescription"),
            file_version: find("FileVersion"),
            internal_name: find("InternalName"),
            legal_copyright: find("LegalCopyright"),
            legal_trademarks: find("LegalTrademarks"),
            original_filename: find("OriginalFilename"),
            private_build: find("PrivateBuild"),
            product_name: find("ProductName"),
            product_version: find("ProductVersion"),
            special_build: find("SpecialBuild"),
        }
    }

    /// Stringize the [`StringFileInfo::comments`] slice into a [`String`].
    pub fn comments(&self) -> Option<String> {
        self.comments.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::company_name`] slice into a [`String`].
    pub fn company_name(&self) -> Option<String> {
        self.company_name.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::file_description`] slice into a [`String`].
    pub fn file_description(&self) -> Option<String> {
        self.file_description.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::file_version`] slice into a [`String`].
    pub fn file_version(&self) -> Option<String> {
        self.file_version.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::internal_name`] slice into a [`String`].
    pub fn internal_name(&self) -> Option<String> {
        self.internal_name.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::legal_copyright`] slice into a [`String`].
    pub fn legal_copyright(&self) -> Option<String> {
        self.legal_copyright.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::legal_trademarks`] slice into a [`String`].
    pub fn legal_trademarks(&self) -> Option<String> {
        self.legal_trademarks.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::original_filename`] slice into a [`String`].
    pub fn original_filename(&self) -> Option<String> {
        self.original_filename.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::private_build`] slice into a [`String`].
    pub fn private_build(&self) -> Option<String> {
        self.private_build.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::product_name`] slice into a [`String`].
    pub fn product_name(&self) -> Option<String> {
        self.product_name.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::product_version`] slice into a [`String`].
    pub fn product_version(&self) -> Option<String> {
        self.product_version.map(|x| to_utf16_string(x))
    }

    /// Stringize the [`StringFileInfo::special_build`] slice into a [`String`].
    pub fn special_build(&self) -> Option<String> {
        self.special_build.map(|x| to_utf16_string(x))
    }
}

/// Represents a version information
#[derive(Copy, Clone)]
pub struct VersionInfo<'a> {
    /// Raw data of entire [`RT_VERSION`] area.
    data: &'a [u8],
    /// Fixed file information.
    pub fixed_info: Option<VsFixedFileInfo>,
    /// Dynamic key-value file information.
    pub string_info: StringFileInfo<'a>,
}

impl fmt::Debug for VersionInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionInfo")
            .field(
                "data",
                &format_args!("{:02x?} ({} bytes)", &self.data, self.data.len()),
            )
            .field("fixed_info", &self.fixed_info)
            .field("string_info", &self.string_info)
            .finish()
    }
}

impl<'a> VersionInfo<'a> {
    pub fn parse(
        pe: &'a [u8],
        bytes: &'a [u8],
        it: ResourceEntryIterator<'a>,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        opts: &options::ParseOptions,
    ) -> error::Result<Option<Self>> {
        if let Some(entry) = it.find_by_id(RT_VERSION)? {
            let offset_to_data =
                match entry.recursive_next_depth(bytes, |e| e.offset_to_data().is_none())? {
                    Some(next) => match next.offset_to_data() {
                        Some(offset_to_data) => offset_to_data,
                        None => return Ok(None),
                    },
                    None => return Ok(None),
                };
            let mut offset = offset_to_data as usize;
            let data_entry = bytes.gread_with::<ResourceDataEntry>(&mut offset, scroll::LE)?;
            let rva = data_entry.offset_to_data as usize;
            offset = utils::find_offset(rva, sections, file_alignment, opts).ok_or_else(|| {
                error::Error::Malformed(format!(
                    "Cannot map ResourceDataEntry rva {:#x} into offset",
                    rva
                ))
            })?;

            if offset + data_entry.size as usize > pe.len() {
                return Err(error::Error::Malformed(format!(
                    "offset ({:#x}) and data_entry.size ({:#x}) is greater than pe len {:#x}",
                    offset,
                    data_entry.size,
                    bytes.len()
                )));
            }
            let data = &pe[offset..offset + data_entry.size as usize];
            let iterator = ResourceStringIterator { data };
            let strings = iterator.collect::<Result<Vec<_>, _>>()?;

            let fixed_info = match strings
                .iter()
                .find(|x| x.key_string() == VS_VERSION_INFO_KEY)
            {
                Some(version_info) => Some(version_info.value.pread_with(0, scroll::LE)?),
                None => None,
            };
            let string_info = StringFileInfo::from_resource_string_iterator(iterator);

            Ok(Some(Self {
                data,
                fixed_info,
                string_info,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Represents a manifest data within resource in the PE (Portable Executable) format.
#[derive(Copy, Clone, Default)]
pub struct ManifestData<'a> {
    /// The raw binary data of the manifest
    pub data: &'a [u8],
}

impl fmt::Debug for ManifestData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ManifestData")
            .field("value", &format_args!("{:02x?}", self.data))
            .finish()
    }
}

impl<'a> ManifestData<'a> {
    pub fn parse(
        pe: &'a [u8],
        bytes: &'a [u8],
        it: ResourceEntryIterator<'a>,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        opts: &options::ParseOptions,
    ) -> error::Result<Option<Self>> {
        if let Some(entry) = it.find_by_id(RT_MANIFEST)? {
            let offset_to_data =
                match entry.recursive_next_depth(bytes, |e| e.offset_to_data().is_none())? {
                    Some(next) => match next.offset_to_data() {
                        Some(offset_to_data) => offset_to_data,
                        None => return Ok(None),
                    },
                    None => return Ok(None),
                };
            let mut offset = offset_to_data as usize;
            let data_entry = bytes.gread_with::<ResourceDataEntry>(&mut offset, scroll::LE)?;
            let rva = data_entry.offset_to_data as usize;
            offset = utils::find_offset(rva, sections, file_alignment, opts).ok_or_else(|| {
                error::Error::Malformed(format!(
                    "Cannot map ResourceDataEntry rva {:#x} into offset",
                    rva
                ))
            })?;

            if offset + data_entry.size as usize > pe.len() {
                return Err(error::Error::Malformed(format!(
                    "offset ({:#x}) and data_entry.size ({:#x}) is greater than pe len {:#x}",
                    offset,
                    data_entry.size,
                    bytes.len()
                )));
            }
            let data = &pe[offset..offset + data_entry.size as usize];
            Ok(Some(Self { data }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ResourceEntry, ResourceStringIterator, VersionField, VFT_APP, VOS_NT_WINDOWS32,
        VS_FFI_FILEFLAGSMASK, VS_FFI_SIGNATURE, VS_FFI_STRUCVERSION, VS_VERSION_INFO_KEY,
    };

    const HAS_NO_RES: &[u8] = include_bytes!("../../tests/bins/pe/has_no_res.exe.bin");
    const HAS_RES_FULL_VERSION_AND_MANIFEST: &[u8] =
        include_bytes!("../../tests/bins/pe/has_res_full_version_and_manifest.exe.bin");

    /// Binary representation of following default LLD manifest (`/MANIFEST`) expect as UTF-8.
    ///
    /// ```xml
    /// <?xml version='1.0' encoding='UTF-8' standalone='yes'?>
    /// <assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>
    ///     <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    ///         <security>
    ///             <requestedPrivileges>
    ///                 <requestedExecutionLevel level='asInvoker' uiAccess='false' />
    ///             </requestedPrivileges>
    ///         </security>
    ///     </trustInfo>
    /// </assembly>
    ///
    /// ```
    ///
    /// NOTE: Break on last line is intentional.
    const EXPECTED_MANIFEST: &[u8; 413] = &[
        0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3D, 0x27,
        0x31, 0x2E, 0x30, 0x27, 0x20, 0x65, 0x6E, 0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67, 0x3D, 0x27,
        0x55, 0x54, 0x46, 0x2D, 0x38, 0x27, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x6C, 0x6F,
        0x6E, 0x65, 0x3D, 0x27, 0x79, 0x65, 0x73, 0x27, 0x3F, 0x3E, 0x0D, 0x0A, 0x3C, 0x61, 0x73,
        0x73, 0x65, 0x6D, 0x62, 0x6C, 0x79, 0x20, 0x78, 0x6D, 0x6C, 0x6E, 0x73, 0x3D, 0x27, 0x75,
        0x72, 0x6E, 0x3A, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2D, 0x6D, 0x69, 0x63, 0x72,
        0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2D, 0x63, 0x6F, 0x6D, 0x3A, 0x61, 0x73, 0x6D, 0x2E, 0x76,
        0x31, 0x27, 0x20, 0x6D, 0x61, 0x6E, 0x69, 0x66, 0x65, 0x73, 0x74, 0x56, 0x65, 0x72, 0x73,
        0x69, 0x6F, 0x6E, 0x3D, 0x27, 0x31, 0x2E, 0x30, 0x27, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x20,
        0x20, 0x3C, 0x74, 0x72, 0x75, 0x73, 0x74, 0x49, 0x6E, 0x66, 0x6F, 0x20, 0x78, 0x6D, 0x6C,
        0x6E, 0x73, 0x3D, 0x22, 0x75, 0x72, 0x6E, 0x3A, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73,
        0x2D, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2D, 0x63, 0x6F, 0x6D, 0x3A,
        0x61, 0x73, 0x6D, 0x2E, 0x76, 0x33, 0x22, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x3C, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x3E, 0x0D, 0x0A,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x3C, 0x72, 0x65,
        0x71, 0x75, 0x65, 0x73, 0x74, 0x65, 0x64, 0x50, 0x72, 0x69, 0x76, 0x69, 0x6C, 0x65, 0x67,
        0x65, 0x73, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x3C, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x65,
        0x64, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x69, 0x6F, 0x6E, 0x4C, 0x65, 0x76, 0x65, 0x6C,
        0x20, 0x6C, 0x65, 0x76, 0x65, 0x6C, 0x3D, 0x27, 0x61, 0x73, 0x49, 0x6E, 0x76, 0x6F, 0x6B,
        0x65, 0x72, 0x27, 0x20, 0x75, 0x69, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3D, 0x27, 0x66,
        0x61, 0x6C, 0x73, 0x65, 0x27, 0x20, 0x2F, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x3C, 0x2F, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73,
        0x74, 0x65, 0x64, 0x50, 0x72, 0x69, 0x76, 0x69, 0x6C, 0x65, 0x67, 0x65, 0x73, 0x3E, 0x0D,
        0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x3C, 0x2F, 0x73, 0x65, 0x63, 0x75,
        0x72, 0x69, 0x74, 0x79, 0x3E, 0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x3C, 0x2F, 0x74, 0x72,
        0x75, 0x73, 0x74, 0x49, 0x6E, 0x66, 0x6F, 0x3E, 0x0D, 0x0A, 0x3C, 0x2F, 0x61, 0x73, 0x73,
        0x65, 0x6D, 0x62, 0x6C, 0x79, 0x3E, 0x0D, 0x0A,
    ];

    /// Binary representation of entire [`super::RT_VERSION`] data of `python-3.11.3-amd64.exe`
    /// to be coverted to appropriate [`super::VersionInfo`]
    ///
    /// This buffer is not aligned with 8 bytes and has no paddings
    const PYTHON_INSTALLER_VERSION_INFO: &[u8; 876] = &[
        0x78, 0x03, 0x34, 0x00, 0x00, 0x00, 0x56, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x56, 0x00, 0x45,
        0x00, 0x52, 0x00, 0x53, 0x00, 0x49, 0x00, 0x4F, 0x00, 0x4E, 0x00, 0x5F, 0x00, 0x49, 0x00,
        0x4E, 0x00, 0x46, 0x00, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBD, 0x04, 0xEF, 0xFE, 0x00,
        0x00, 0x01, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x00, 0x00, 0x4E, 0x0C, 0x0B, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x4E, 0x0C, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0xD8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x74, 0x00,
        0x72, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x67, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65,
        0x00, 0x49, 0x00, 0x6E, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x00, 0x00, 0xB4, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x30, 0x00, 0x34, 0x00, 0x30, 0x00, 0x39, 0x00, 0x30, 0x00, 0x34, 0x00, 0x45,
        0x00, 0x34, 0x00, 0x00, 0x00, 0x58, 0x00, 0x36, 0x00, 0x00, 0x00, 0x43, 0x00, 0x6F, 0x00,
        0x6D, 0x00, 0x70, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x79, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D,
        0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x79, 0x00, 0x74, 0x00, 0x68, 0x00,
        0x6F, 0x00, 0x6E, 0x00, 0x20, 0x00, 0x53, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0x77,
        0x00, 0x61, 0x00, 0x72, 0x00, 0x65, 0x00, 0x20, 0x00, 0x46, 0x00, 0x6F, 0x00, 0x75, 0x00,
        0x6E, 0x00, 0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x58, 0x00, 0x2E, 0x00, 0x00, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00,
        0x65, 0x00, 0x44, 0x00, 0x65, 0x00, 0x73, 0x00, 0x63, 0x00, 0x72, 0x00, 0x69, 0x00, 0x70,
        0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00,
        0x79, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x20, 0x00, 0x33, 0x00, 0x2E,
        0x00, 0x31, 0x00, 0x31, 0x00, 0x2E, 0x00, 0x33, 0x00, 0x20, 0x00, 0x28, 0x00, 0x36, 0x00,
        0x34, 0x00, 0x2D, 0x00, 0x62, 0x00, 0x69, 0x00, 0x74, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x38, 0x00, 0x18, 0x00, 0x00, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00,
        0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x33, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x31, 0x00, 0x2E, 0x00, 0x33, 0x00,
        0x31, 0x00, 0x35, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x06,
        0x00, 0x01, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00,
        0x61, 0x00, 0x6C, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x00, 0x00, 0x73,
        0x00, 0x65, 0x00, 0x74, 0x00, 0x75, 0x00, 0x70, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x7E, 0x00,
        0x00, 0x00, 0x4C, 0x00, 0x65, 0x00, 0x67, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x43, 0x00, 0x6F,
        0x00, 0x70, 0x00, 0x79, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x68, 0x00, 0x74, 0x00,
        0x00, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x79, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67,
        0x00, 0x68, 0x00, 0x74, 0x00, 0x20, 0x00, 0x28, 0x00, 0x63, 0x00, 0x29, 0x00, 0x20, 0x00,
        0x50, 0x00, 0x79, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x20, 0x00, 0x53,
        0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0x77, 0x00, 0x61, 0x00, 0x72, 0x00, 0x65, 0x00,
        0x20, 0x00, 0x46, 0x00, 0x6F, 0x00, 0x75, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x61, 0x00, 0x74,
        0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x2E, 0x00, 0x20, 0x00, 0x41, 0x00, 0x6C, 0x00,
        0x6C, 0x00, 0x20, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x68, 0x00, 0x74, 0x00, 0x73,
        0x00, 0x20, 0x00, 0x72, 0x00, 0x65, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
        0x65, 0x00, 0x64, 0x00, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x30, 0x00, 0x00,
        0x00, 0x4F, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x61, 0x00,
        0x6C, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6D,
        0x00, 0x65, 0x00, 0x00, 0x00, 0x70, 0x00, 0x79, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6F, 0x00,
        0x6E, 0x00, 0x2D, 0x00, 0x33, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x31, 0x00, 0x2E, 0x00, 0x33,
        0x00, 0x2D, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x64, 0x00, 0x36, 0x00, 0x34, 0x00, 0x2E, 0x00,
        0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x00, 0x00, 0x50, 0x00, 0x2E, 0x00, 0x00, 0x00, 0x50,
        0x00, 0x72, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00, 0x63, 0x00, 0x74, 0x00, 0x4E, 0x00,
        0x61, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x79, 0x00, 0x74,
        0x00, 0x68, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x20, 0x00, 0x33, 0x00, 0x2E, 0x00, 0x31, 0x00,
        0x31, 0x00, 0x2E, 0x00, 0x33, 0x00, 0x20, 0x00, 0x28, 0x00, 0x36, 0x00, 0x34, 0x00, 0x2D,
        0x00, 0x62, 0x00, 0x69, 0x00, 0x74, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00, 0x63,
        0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6F, 0x00,
        0x6E, 0x00, 0x00, 0x00, 0x33, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x31, 0x00, 0x2E, 0x00, 0x33,
        0x00, 0x31, 0x00, 0x35, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x00, 0x00, 0x44, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x56, 0x00, 0x61, 0x00, 0x72, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C,
        0x00, 0x65, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x04, 0x00, 0x00, 0x00, 0x54, 0x00, 0x72, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x73,
        0x00, 0x6C, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x09, 0x04, 0xE4, 0x04,
    ];

    /// Binary representation of entire [`super::RT_VERSION`] data of `python-3.11.3-amd64.exe`
    /// to be coverted to appropriate [`super::VersionInfo`]
    ///
    /// Unlike [`PYTHON_INSTALLER_VERSION_INFO`], this buffer is aligned with 8 bytes and has
    /// 4 bytes paddings at the tail
    const NTDLL_VERSION_INFO: &[u8; 896] = &[
        0x7C, 0x03, 0x34, 0x00, 0x00, 0x00, 0x56, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x56, 0x00, 0x45,
        0x00, 0x52, 0x00, 0x53, 0x00, 0x49, 0x00, 0x4F, 0x00, 0x4E, 0x00, 0x5F, 0x00, 0x49, 0x00,
        0x4E, 0x00, 0x46, 0x00, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBD, 0x04, 0xEF, 0xFE, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0xAA, 0x11, 0x61, 0x4A, 0x00, 0x00, 0x0A, 0x00,
        0xAA, 0x11, 0x61, 0x4A, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xDC, 0x02, 0x00, 0x00, 0x01, 0x00, 0x53, 0x00, 0x74, 0x00, 0x72, 0x00, 0x69,
        0x00, 0x6E, 0x00, 0x67, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x49, 0x00,
        0x6E, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x00, 0x00, 0xB8, 0x02, 0x00, 0x00, 0x01, 0x00, 0x30,
        0x00, 0x34, 0x00, 0x30, 0x00, 0x39, 0x00, 0x30, 0x00, 0x34, 0x00, 0x42, 0x00, 0x30, 0x00,
        0x00, 0x00, 0x4C, 0x00, 0x16, 0x00, 0x01, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x70,
        0x00, 0x61, 0x00, 0x6E, 0x00, 0x79, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x73,
        0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x72, 0x00,
        0x70, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E,
        0x00, 0x00, 0x00, 0x42, 0x00, 0x0D, 0x00, 0x01, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00,
        0x65, 0x00, 0x44, 0x00, 0x65, 0x00, 0x73, 0x00, 0x63, 0x00, 0x72, 0x00, 0x69, 0x00, 0x70,
        0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x00,
        0x54, 0x00, 0x20, 0x00, 0x4C, 0x00, 0x61, 0x00, 0x79, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20,
        0x00, 0x44, 0x00, 0x4C, 0x00, 0x4C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6E, 0x00, 0x27, 0x00,
        0x01, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72,
        0x00, 0x73, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00,
        0x30, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x39, 0x00, 0x30, 0x00, 0x34,
        0x00, 0x31, 0x00, 0x2E, 0x00, 0x34, 0x00, 0x35, 0x00, 0x32, 0x00, 0x32, 0x00, 0x20, 0x00,
        0x28, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x42, 0x00, 0x75, 0x00, 0x69, 0x00, 0x6C,
        0x00, 0x64, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x36, 0x00, 0x30, 0x00, 0x31, 0x00, 0x30, 0x00,
        0x31, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x38, 0x00, 0x30, 0x00, 0x30, 0x00, 0x29, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x34, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x74, 0x00,
        0x65, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D,
        0x00, 0x65, 0x00, 0x00, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00,
        0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x80, 0x00, 0x2E, 0x00, 0x01,
        0x00, 0x4C, 0x00, 0x65, 0x00, 0x67, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x43, 0x00, 0x6F, 0x00,
        0x70, 0x00, 0x79, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00, 0x68, 0x00, 0x74, 0x00, 0x00,
        0x00, 0xA9, 0x00, 0x20, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00,
        0x73, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x72,
        0x00, 0x70, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00,
        0x6E, 0x00, 0x2E, 0x00, 0x20, 0x00, 0x41, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x20, 0x00, 0x72,
        0x00, 0x69, 0x00, 0x67, 0x00, 0x68, 0x00, 0x74, 0x00, 0x73, 0x00, 0x20, 0x00, 0x72, 0x00,
        0x65, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x64, 0x00, 0x2E,
        0x00, 0x00, 0x00, 0x3C, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x4F, 0x00, 0x72, 0x00, 0x69, 0x00,
        0x67, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C,
        0x00, 0x65, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x00, 0x00, 0x6E, 0x00,
        0x74, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C,
        0x00, 0x00, 0x00, 0x6A, 0x00, 0x25, 0x00, 0x01, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00,
        0x64, 0x00, 0x75, 0x00, 0x63, 0x00, 0x74, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00,
        0x73, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00, 0xAE, 0x00, 0x20, 0x00, 0x57, 0x00, 0x69,
        0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0xAE, 0x00, 0x20, 0x00,
        0x4F, 0x00, 0x70, 0x00, 0x65, 0x00, 0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6E,
        0x00, 0x67, 0x00, 0x20, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00,
        0x6D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x10, 0x00, 0x01, 0x00, 0x50, 0x00, 0x72,
        0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00, 0x63, 0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x31, 0x00, 0x30,
        0x00, 0x2E, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x39, 0x00, 0x30, 0x00, 0x34, 0x00,
        0x31, 0x00, 0x2E, 0x00, 0x34, 0x00, 0x35, 0x00, 0x32, 0x00, 0x32, 0x00, 0x00, 0x00, 0x44,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x56, 0x00, 0x61, 0x00, 0x72, 0x00, 0x46, 0x00, 0x69, 0x00,
        0x6C, 0x00, 0x65, 0x00, 0x49, 0x00, 0x6E, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x24, 0x00, 0x04, 0x00, 0x00, 0x00, 0x54, 0x00, 0x72, 0x00, 0x61, 0x00, 0x6E, 0x00,
        0x73, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x09, 0x04, 0xB0, 0x04, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_resource_entry_unions() {
        let entry = ResourceEntry::from(0x8000183880002938);
        assert_eq!(entry.name_is_string(), true);
        assert_eq!(entry.name_offset(), 0x1838);
        assert_eq!(entry.id(), None);
        assert_eq!(entry.data_is_directory(), true);
        assert_eq!(entry.offset_to_directory(), 0x2938);
        assert_eq!(entry.value(), 0x8000183880002938);

        let entry = ResourceEntry::from(0x183880002938);
        assert_eq!(entry.name_is_string(), false);
        assert_eq!(entry.name_offset(), 0x1838); // invalid, just for assertion
        assert_eq!(entry.id(), Some(6200)); // invalid, just for assertion
        assert_eq!(entry.data_is_directory(), true);
        assert_eq!(entry.offset_to_directory(), 0x2938);
        assert_eq!(entry.value(), 0x183880002938);

        let entry = ResourceEntry::from(0x8000183800002938);
        assert_eq!(entry.name_is_string(), true);
        assert_eq!(entry.name_offset(), 0x1838);
        assert_eq!(entry.id(), None);
        assert_eq!(entry.data_is_directory(), false);
        assert_eq!(entry.offset_to_directory(), 0x2938);
        assert_eq!(entry.value(), 0x8000183800002938);

        let entry = ResourceEntry::from(0x208800008080);
        assert_eq!(entry.name_is_string(), false);
        assert_eq!(entry.name_offset(), 0x2088); // invalid, just for assertion
        assert_eq!(entry.id(), Some(8328)); // invalid, just for assertion
        assert_eq!(entry.data_is_directory(), false);
        assert_eq!(entry.offset_to_directory(), 0x8080);
        assert_eq!(entry.value(), 0x208800008080);

        let entry = ResourceEntry::from(0x3880008080);
        assert_eq!(entry.name_is_string(), false);
        assert_eq!(entry.id(), Some(56));
        assert_eq!(entry.data_is_directory(), true);
        assert_eq!(entry.offset_to_directory(), 0x8080);
        assert_eq!(entry.value(), 0x3880008080);
    }

    #[test]
    fn test_version_field_from_ms_ls() {
        const MS: u32 = (4 << 16) | 2; // major: 4, minor: 2
        const LS: u32 = (3 << 16) | 1; // build: 3, revision: 1

        let mut version = VersionField::from_ms_ls(MS, LS);

        assert_eq!(version.major, 4);
        assert_eq!(version.minor, 2);
        assert_eq!(version.build, 3);
        assert_eq!(version.revision, 1);

        assert_eq!(version.to_string(), "4.2.3.1");
        assert_eq!(version.to_ms(), MS);
        assert_eq!(version.to_ls(), LS);

        version.major += 1;
        version.minor += 2;
        assert_eq!(version.to_ms(), (4 + 1 << 16) | 2 + 2);
        version.build += 3;
        version.revision += 4;
        assert_eq!(version.to_ls(), (3 + 3 << 16) | 1 + 4);
    }

    #[test]
    fn parse_no_resource() {
        let binary = crate::pe::PE::parse(HAS_NO_RES).expect("Unable to parse binary");
        assert_eq!(binary.resource_data.is_none(), true);
    }

    #[test]
    fn parse_full_version_and_manifest() {
        let binary = crate::pe::PE::parse(HAS_RES_FULL_VERSION_AND_MANIFEST)
            .expect("Unable to parse binary");
        assert_eq!(binary.resource_data.is_some(), true);
        let res_data = binary.resource_data.unwrap();
        assert_eq!(res_data.version_info.is_some(), true);
        let ver_info = res_data.version_info.unwrap();

        assert_eq!(ver_info.fixed_info.is_some(), true);
        let fixed_info = ver_info.fixed_info.unwrap();
        assert_eq!(fixed_info.signature, VS_FFI_SIGNATURE);
        assert_eq!(fixed_info.is_valid(), true);
        assert_eq!(fixed_info.struct_version, VS_FFI_STRUCVERSION);
        assert_eq!(fixed_info.file_version_ms, 0x1);
        assert_eq!(fixed_info.file_version_ls, 0x0);
        assert_eq!(fixed_info.product_version_ms, 0x1);
        assert_eq!(fixed_info.product_version_ls, 0x0);
        assert_eq!(fixed_info.file_flags_mask, VS_FFI_FILEFLAGSMASK);
        assert_eq!(fixed_info.file_flags, 0x0);
        assert_eq!(fixed_info.file_os, VOS_NT_WINDOWS32);
        assert_eq!(fixed_info.file_type, VFT_APP);
        assert_eq!(fixed_info.file_subtype, 0x0);
        assert_eq!(fixed_info.file_date_ms, 0x0);
        assert_eq!(fixed_info.file_date_ls, 0x0);

        let str_info = ver_info.string_info;
        assert_eq!(
            str_info.comments(),
            Some(String::from("GOBLIN-TEST-BIN-COMMENTS"))
        );
        assert_eq!(
            str_info.company_name(),
            Some(String::from("GOBLIN-TEST-BIN-COMPANY-NAME"))
        );
        assert_eq!(
            str_info.file_description(),
            Some(String::from("GOBLIN-TEST-BIN-FILE-DESCRIPTION"))
        );
        assert_eq!(
            str_info.file_version(),
            Some(String::from("GOBLIN-TEST-BIN-FILE-VERSION"))
        );
        assert_eq!(
            str_info.internal_name(),
            Some(String::from("GOBLIN-TEST-BIN-INTERNAL-NAME"))
        );
        assert_eq!(
            str_info.legal_copyright(),
            Some(String::from("GOBLIN-TEST-BIN-LEGAL-COPYRIGHT"))
        );
        assert_eq!(
            str_info.legal_trademarks(),
            Some(String::from("GOBLIN-TEST-BIN-LEGAL-TRADEMARKS"))
        );
        assert_eq!(
            str_info.original_filename(),
            Some(String::from("GOBLIN-TEST-BIN-ORIGINAL-FILENAME"))
        );
        assert_eq!(
            str_info.private_build(),
            Some(String::from("GOBLIN-TEST-BIN-PRIVATE-BUILD"))
        );
        assert_eq!(
            str_info.product_name(),
            Some(String::from("GOBLIN-TEST-BIN-PRODUCT-NAME"))
        );
        assert_eq!(
            str_info.product_version(),
            Some(String::from("GOBLIN-TEST-BIN-PRODUCT-VERSION"))
        );
        assert_eq!(
            str_info.special_build(),
            Some(String::from("GOBLIN-TEST-BIN-SPECIAL-BUILD"))
        );

        assert_eq!(res_data.manifest_data.is_some(), true);
        let manifest_info = res_data.manifest_data.unwrap();
        assert_eq!(manifest_info.data, EXPECTED_MANIFEST);
    }

    #[test]
    fn test_resource_string_iterator() {
        // NOT Aligned with 8 bytes and has no paddings
        let it = ResourceStringIterator {
            data: PYTHON_INSTALLER_VERSION_INFO,
        };
        let it_vec = it.collect::<Result<Vec<_>, _>>();
        assert_eq!(it_vec.is_ok(), true);
        let it_vec = it_vec.unwrap();

        assert_eq!(it_vec[0].is_binary_data(), true);
        assert_eq!(it_vec[0].key_string(), VS_VERSION_INFO_KEY);
        assert_eq!(
            it_vec[0].value,
            &[
                0xbd, 0x04, 0xef, 0xfe, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x00, 0x00,
                0x4e, 0x0c, 0x0b, 0x00, 0x03, 0x00, 0x00, 0x00, 0x4e, 0x0c, 0x3f, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xd8, 0x02,
                0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x74, 0x00, 0x72, 0x00
            ]
        );

        assert_eq!(it_vec[1].r#type, 103); // Invalid, seems broken by RC (resource compiler)
        assert_eq!(it_vec[1].key_string(), "FileInfo");
        assert_eq!(
            it_vec[1].value,
            &[
                0xb4, 0x02, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x34, 0x00, 0x30, 0x00, 0x39, 0x00,
                0x30, 0x00, 0x34, 0x00, 0x45, 0x00, 0x34, 0x00, 0x00, 0x00, 0x58, 0x00, 0x36, 0x00,
                0x00, 0x00, 0x43, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x70, 0x00, 0x61, 0x00, 0x6e, 0x00,
                0x79, 0x00, 0x4e, 0x00, 0x61, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x50, 0x00, 0x79, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x20, 0x00,
                0x53, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x77, 0x00, 0x61, 0x00, 0x72, 0x00,
                0x65, 0x00, 0x20, 0x00, 0x46, 0x00, 0x6f, 0x00, 0x75, 0x00, 0x6e, 0x00, 0x64, 0x00,
                0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );

        assert_eq!(it_vec[2].is_binary_data(), true);
        assert_eq!(it_vec[2].key_string(), "FileDescription");
        assert_eq!(it_vec[2].value_string(), "Python 3.11.3 (64-bit)");
        assert_eq!(
            it_vec[2].value,
            &[
                0x50, 0x00, 0x79, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x20, 0x00,
                0x33, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x20, 0x00,
                0x28, 0x00, 0x36, 0x00, 0x34, 0x00, 0x2d, 0x00, 0x62, 0x00, 0x69, 0x00, 0x74, 0x00,
                0x29, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );

        assert_eq!(it_vec[3].is_binary_data(), true);
        assert_eq!(it_vec[3].key_string(), "FileVersion");
        assert_eq!(it_vec[3].value_string(), "3.11.3150.0");
        assert_eq!(
            it_vec[3].value,
            &[
                0x33, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x31, 0x00,
                0x35, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x00, 0x00,
            ]
        );

        assert_eq!(it_vec[4].is_text_data(), true);
        assert_eq!(it_vec[4].key_string(), "InternalName");
        assert_eq!(it_vec[4].value_string(), "setup");
        assert_eq!(
            it_vec[4].value,
            &[0x73, 0x00, 0x65, 0x00, 0x74, 0x00, 0x75, 0x00, 0x70, 0x00, 0x00, 0x00,]
        );

        assert_eq!(it_vec[5].is_binary_data(), true);
        assert_eq!(it_vec[5].key_string(), "LegalCopyright");
        assert_eq!(
            it_vec[5].value_string(),
            "Copyright (c) Python Software Foundation. All rights reserved."
        );
        assert_eq!(
            it_vec[5].value,
            &[
                0x43, 0x00, 0x6f, 0x00, 0x70, 0x00, 0x79, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00,
                0x68, 0x00, 0x74, 0x00, 0x20, 0x00, 0x28, 0x00, 0x63, 0x00, 0x29, 0x00, 0x20, 0x00,
                0x50, 0x00, 0x79, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x20, 0x00,
                0x53, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x77, 0x00, 0x61, 0x00, 0x72, 0x00,
                0x65, 0x00, 0x20, 0x00, 0x46, 0x00, 0x6f, 0x00, 0x75, 0x00, 0x6e, 0x00, 0x64, 0x00,
                0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x2e, 0x00, 0x20, 0x00,
                0x41, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x72, 0x00, 0x69, 0x00, 0x67, 0x00,
                0x68, 0x00, 0x74, 0x00, 0x73, 0x00, 0x20, 0x00, 0x72, 0x00, 0x65, 0x00, 0x73, 0x00,
                0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x64, 0x00, 0x2e, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
        );

        assert_eq!(it_vec[6].is_binary_data(), true);
        assert_eq!(it_vec[6].key_string(), "OriginalFilename");
        assert_eq!(it_vec[6].value_string(), "python-3.11.3-amd64.exe");
        assert_eq!(
            it_vec[6].value,
            &[
                0x70, 0x00, 0x79, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x2d, 0x00,
                0x33, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x2d, 0x00,
                0x61, 0x00, 0x6d, 0x00, 0x64, 0x00, 0x36, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x65, 0x00,
                0x78, 0x00, 0x65, 0x00, 0x00, 0x00,
            ]
        );

        assert_eq!(it_vec[7].is_binary_data(), true);
        assert_eq!(it_vec[7].key_string(), "ProductName");
        assert_eq!(it_vec[7].value_string(), "Python 3.11.3 (64-bit)");
        assert_eq!(
            it_vec[7].value,
            &[
                0x50, 0x00, 0x79, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x20, 0x00,
                0x33, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x20, 0x00,
                0x28, 0x00, 0x36, 0x00, 0x34, 0x00, 0x2d, 0x00, 0x62, 0x00, 0x69, 0x00, 0x74, 0x00,
                0x29, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );

        assert_eq!(it_vec[8].is_binary_data(), true);
        assert_eq!(it_vec[8].key_string(), "ProductVersion");
        assert_eq!(it_vec[8].value_string(), "3.11.3150.0");
        assert_eq!(
            it_vec[8].value,
            &[
                0x33, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x31, 0x00,
                0x35, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x00, 0x00,
            ]
        );

        assert_eq!(it_vec[9].is_binary_data(), true);
        assert_eq!(it_vec[9].key_string(), "VarFileInfo");
        assert_eq!(it_vec[9].value, &[]);

        assert_eq!(it_vec[9].is_binary_data(), true);
        assert_eq!(it_vec[10].key_string(), "Translation");
        assert_eq!(it_vec[10].value, &[0x09, 0x04, 0xe4, 0x04]);

        assert_eq!(it_vec.get(11), None);

        // Aligned with 8 bytes and has 4 bytes zero paddings at the tail
        let it = ResourceStringIterator {
            data: NTDLL_VERSION_INFO,
        };
        let it_vec = it.collect::<Result<Vec<_>, _>>();
        assert_eq!(it_vec.is_ok(), true);
    }
}
