use crate::error;
use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::iter::FusedIterator;
use core::ops::Not;
use log::debug;
use scroll::{Pread, Pwrite, SizeWith};

use crate::pe::data_directories;
use crate::pe::options;
use crate::pe::section_table;
use crate::pe::utils;

use super::import::Bitfield;

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

/// [`ClrData::signature`]: Indicates a valid signature gathered from first 4-bytes of [`Cor20Header::metadata`] (`'BSJB'`)
pub const DOTNET_SIGNATURE: u32 = 0x424A5342;

/// Representsa CLR data in a PE file
#[derive(PartialEq, Copy, Clone, Default)]
pub struct ClrData<'a> {
    /// The .NET signature gathered from first 4-bytes of [`Cor20Header::metadata`] must equals to [`DOTNET_SIGNATURE`].
    pub signature: u32,
    /// The COR20 header contains metadatas about the IL.
    pub cor20_header: Cor20Header,
    /// The storage header from [`Cor20Header::metadata`].
    pub storage_header: StorageHeader,
    /// The metadata header (aka Storage Header) from [`Cor20Header::metadata`].
    pub metadata_header: StorageSignature<'a>,
    /// The raw bytes of [`Cor20Header::metadata`].
    pub metadata_data: &'a [u8],
    /// How many bytes ([`ClrData::storage_header`] + [`ClrData::metadata_header`]) were skipped in [`ClrData::metadata_data`] prologue.
    pub offset_of_metadata: usize,
}

impl<'a> fmt::Debug for ClrData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClrData")
            .field(
                "signature",
                &format_args!(
                    "{:#x} ({})",
                    self.signature,
                    if self.is_valid() {
                        "Correct"
                    } else {
                        "Incorrect"
                    }
                ),
            )
            .field("cor20_header", &self.cor20_header)
            .field("metadata_header", &self.metadata_header)
            .finish()
    }
}

impl<'a> ClrData<'a> {
    pub fn parse(
        bytes: &'a [u8],
        dd: &data_directories::DataDirectory,
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
        dd: &data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        opts: &options::ParseOptions,
    ) -> error::Result<Self> {
        let rva = dd.virtual_address as usize;
        let offset = utils::find_offset(rva, sections, file_alignment, opts).ok_or_else(|| {
            error::Error::Malformed(format!(
                "Cannot map COM descriptor rva {:#x} into offset",
                rva
            ))
        })?;
        let cor20_header = bytes.pread_with::<Cor20Header>(offset, scroll::LE)?;

        let rva = cor20_header.metadata.virtual_address as usize;
        let mut offset =
            utils::find_offset(rva, sections, file_alignment, opts).ok_or_else(|| {
                error::Error::Malformed(format!(
                    "Cannot map COR20 metadata rva {:#x} into offset",
                    rva
                ))
            })?;
        let signature = bytes.pread_with::<u32>(offset, scroll::LE)?;

        if offset + cor20_header.metadata.size as usize > bytes.len() {
            return Err(error::Error::Malformed(format!(
                "COR20 metadata offset ({:#x}) and size ({:#x}) exceeds bytes slice ({:#x})",
                offset,
                cor20_header.metadata.size,
                bytes.len()
            )));
        }
        let saved_offset = offset;
        let metadata_header = StorageSignature::parse(bytes, &mut offset)?;
        let storage_header = bytes.gread_with::<StorageHeader>(&mut offset, scroll::LE)?;
        let offset_of_metadata = offset - saved_offset;
        let metadata_data = &bytes[offset..offset + cor20_header.metadata.size as usize];

        Ok(Self {
            signature,
            cor20_header,
            storage_header,
            metadata_header,
            metadata_data,
            offset_of_metadata,
        })
    }

    /// Returns `true` if [`Self::signature`] matches the [`DOTNET_SIGNATURE`], otherwise `false`.
    pub fn is_valid(&self) -> bool {
        self.signature == DOTNET_SIGNATURE
    }

    /// Returns [`ClrSectionIterator`] that iterates CLR sections
    pub fn sections(&self) -> ClrSectionIterator<'a> {
        ClrSectionIterator {
            storage_header: self.storage_header,
            data: &self.metadata_data,
            index_cursor: 0,
        }
    }

    /// Returns MVID (Module Version IDentifier) from the `#GUID` CLR section if present, otherwise [`None`].
    ///
    /// If this is [`None`] and the [`crate::pe::debug::ReproInfo`] presents, you should use that instead.
    pub fn mvid(&self) -> error::Result<Option<&'a [u8]>> {
        Ok(self
            .sections()
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .find(|x| x.name == b"#GUID\0")
            .map(|x| {
                if x.offset as usize - self.offset_of_metadata + x.size as usize
                    > self.metadata_data.len()
                {
                    Err(error::Error::Malformed(format!(
                        "CLR section offset ({:#x}) and size ({:#x}) exceeds metadata slice ({:#x})",
                        x.offset,
                        x.size as usize - self.offset_of_metadata,
                        self.metadata_data.len()
                    )))
                } else {
                    Ok(
                        &self.metadata_data[x.offset as usize - self.offset_of_metadata
                            ..x.offset as usize - self.offset_of_metadata + x.size as usize],
                    )
                }
            })
            .transpose()?)
    }
}

/// Represents the .NET COR20 header in a PE file, which includes metadata and flags specific
/// to .NET assemblies. This header is found in the COM descriptor directory of a PE file.
#[repr(C)]
#[derive(PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct Cor20Header {
    /// The size of this structure in bytes.
    pub cb: u32,
    /// Major runtime version number of the CLR.
    pub major_runtime_version: u16,
    /// Minor runtime version number of the CLR.
    pub minor_runtime_version: u16,
    /// The location and size of the metadata section, which contains metadata tables
    /// for the assembly, such as type definitions and member references.
    pub metadata: data_directories::DataDirectory,
    /// Flags that describe characteristics of the assembly (e.g., IL-only, 32-bit preferred).
    ///
    /// Possible values:
    /// - [`COMIMAGE_FLAGS_ILONLY`]
    /// - [`COMIMAGE_FLAGS_32BITREQUIRED`]
    /// - [`COMIMAGE_FLAGS_IL_LIBRARY`]
    /// - [`COMIMAGE_FLAGS_STRONGNAMESIGNED`]
    /// - [`COMIMAGE_FLAGS_NATIVE_ENTRYPOINT`]
    /// - [`COMIMAGE_FLAGS_TRACKDEBUGDATA`]
    /// - [`COMIMAGE_FLAGS_32BITPREFERRED`]
    pub flags: u32,
    /// Token or RVA of the entry point method for the assembly. For DLLs, this can be `0`.
    pub entry_point_token_or_rva: u32,
    /// Data directory specifying resources in the assembly.
    pub resources: data_directories::DataDirectory,
    /// Data directory containing the strong name signature of the assembly, if signed.
    pub strong_name_signature: data_directories::DataDirectory,
    /// Data directory for the code manager table, reserved for internal use.
    pub code_manager_table: data_directories::DataDirectory,
    /// Data directory for vtable fixups, used to fixup vtables in unmanaged code.
    pub vtable_fixups: data_directories::DataDirectory,
    /// Data directory for export address table jumps, which can be used for interop.
    pub export_address_table_jumps: data_directories::DataDirectory,
    /// Data directory for a managed native header, reserved for future use.
    pub managed_native_header: data_directories::DataDirectory,
}

impl fmt::Debug for Cor20Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClrData")
            .field(
                "cb",
                &format_args!(
                    "{:#x} ({})",
                    self.cb,
                    if self.is_cb_correct() {
                        "Correct"
                    } else {
                        "Incorrect"
                    }
                ),
            )
            .field("major_runtime_version", &self.major_runtime_version)
            .field("minor_runtime_version", &self.minor_runtime_version)
            .field("metadata", &format_args!("{:#x?}", &self.metadata))
            .field("flags", &format_args!("{:#x}", &self.flags))
            .field(
                "entry_point_token_or_rva",
                &format_args!("{:#x}", &self.entry_point_token_or_rva),
            )
            .field("resources", &format_args!("{:#x?}", &self.resources))
            .field(
                "strong_name_signature",
                &format_args!("{:#x?}", &self.strong_name_signature),
            )
            .field(
                "code_manager_table",
                &format_args!("{:#x?}", &self.code_manager_table),
            )
            .field(
                "vtable_fixups",
                &format_args!("{:#x?}", &self.vtable_fixups),
            )
            .field(
                "export_address_table_jumps",
                &format_args!("{:#x?}", &self.export_address_table_jumps),
            )
            .field(
                "managed_native_header",
                &format_args!("{:#x?}", &self.managed_native_header),
            )
            .finish()
    }
}

impl Cor20Header {
    /// Returns `true` if [`Cor20Header::cb`] matches size of [`Cor20Header`], otherwise `false`.
    pub fn is_cb_correct(&self) -> bool {
        self.cb as usize == core::mem::size_of::<Cor20Header>()
    }

    /// Whether the assembly contains only IL (Intermediate Language) code.
    pub fn is_il_only(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_ILONLY != 0
    }

    /// Whether the assembly requires a 32-bit environment to run.
    pub fn is_32bit_required(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_32BITREQUIRED != 0
    }

    /// Whether assembly is a library, not a standalone executable.
    pub fn is_il_library(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_IL_LIBRARY != 0
    }

    /// Whether assembly is signed with a strong name.
    pub fn is_strong_name_signed(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_STRONGNAMESIGNED != 0
    }

    /// Whether the entry point for the assembly is a native method.
    pub fn is_native_entrypoint(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0
    }

    /// Whether debug information is tracked for the assembly.
    pub fn is_track_debug_data(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_TRACKDEBUGDATA != 0
    }

    /// Whether the assembly prefers a 32-bit environment if available.
    pub fn is_32bit_preferred(&self) -> bool {
        self.flags & COMIMAGE_FLAGS_32BITPREFERRED != 0
    }
}

/// [`Cor20Header::flags`]: Indicates that the assembly contains only IL (Intermediate Language) code.
pub const COMIMAGE_FLAGS_ILONLY: u32 = 0x00000001;
/// [`Cor20Header::flags`]: Indicates that the assembly requires a 32-bit environment to run.
pub const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x00000002;
/// [`Cor20Header::flags`]: Indicates that the assembly is a library, not a standalone executable.
pub const COMIMAGE_FLAGS_IL_LIBRARY: u32 = 0x00000004;
/// [`Cor20Header::flags`]: Indicates that the assembly is signed with a strong name.
pub const COMIMAGE_FLAGS_STRONGNAMESIGNED: u32 = 0x00000008;
/// [`Cor20Header::flags`]: Indicates that the entry point for the assembly is a native method.
pub const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x00000010;
/// [`Cor20Header::flags`]: Indicates that debug information is tracked for the assembly.
pub const COMIMAGE_FLAGS_TRACKDEBUGDATA: u32 = 0x00010000;
/// [`Cor20Header::flags`]: Indicates that the assembly prefers a 32-bit environment if available,
/// though it can run in a 64-bit environment if necessary.
pub const COMIMAGE_FLAGS_32BITPREFERRED: u32 = 0x00020000;

/// [`Cor20Header::major_runtime_version`]: Indicates the major version of the .NET runtime.
pub const COR_VERSION_MAJOR_V2: u32 = 2;
/// [`Cor20Header::major_runtime_version`]: Indicates the default major runtime version for .NET.
pub const COR_VERSION_MAJOR: u32 = COR_VERSION_MAJOR_V2;
/// [`Cor20Header::minor_runtime_version`]: Indicates the minor version of the .NET runtime.
pub const COR_VERSION_MINOR: u32 = 5;
/// Indicates the length of a "deleted" name in the metadata.
pub const COR_DELETED_NAME_LENGTH: u32 = 8;
/// Indicates the length of a "vtable gap" name in the metadata.
pub const COR_VTABLEGAP_NAME_LENGTH: u32 = 8;

/// Indicates that the vtable is 32-bit.
pub const COR_VTABLE_32BIT: u32 = 0x01;
/// Indicates that the vtable is 64-bit.
pub const COR_VTABLE_64BIT: u32 = 0x02;
/// Indicates that the vtable is callable from unmanaged code.
pub const COR_VTABLE_FROM_UNMANAGED: u32 = 0x04;
/// Indicates that calls retain the AppDomain context when using unmanaged code.
pub const COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN: u32 = 0x08;
/// Indicates that the vtable call invokes the most derived method.
pub const COR_VTABLE_CALL_MOST_DERIVED: u32 = 0x10;

/// Represents the signature structure for a storage header in a .NET metadata stream.
/// This structure identifies the version and format of the metadata.
#[derive(PartialEq, Copy, Clone, Default)]
pub struct StorageSignature<'a> {
    /// Indicates the signature value, used to identify the storage structure.
    pub signature: u32,
    /// Indicates the major version number of the metadata format.
    pub major_version: u16,
    /// Indicates the minor version number of the metadata format.
    pub minor_version: u16,
    /// Indicates the offset to the next structure containing additional metadata information.
    pub extra_data: u32,
    /// Indicates the length of the version string, in bytes.
    pub version_len: u32,
    /// The raw data representation of an null-terminated string with size of [`StorageSignature::version_len`]
    pub version: &'a [u8],
}

impl<'a> fmt::Debug for StorageSignature<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageSignature")
            .field(
                "signature",
                &format_args!(
                    "{:#x} ({})",
                    &self.signature,
                    if self.is_valid() {
                        "Correct"
                    } else {
                        "Incorrect"
                    }
                ),
            )
            .field("major_version", &self.major_version)
            .field("minor_version", &self.minor_version)
            .field("extra_data", &format_args!("{:#x}", &self.extra_data))
            .field("version_len", &format_args!("{:#x}", &self.version_len))
            .field(
                "version",
                &format_args!(
                    "{:?} ({} bytes)",
                    &self.to_version_string(),
                    &self.version_len
                ),
            )
            .finish()
    }
}

impl<'a> StorageSignature<'a> {
    pub fn parse(bytes: &'a [u8], offset: &mut usize) -> error::Result<Self> {
        let signature = bytes.gread_with::<u32>(offset, scroll::LE)?;
        let major_version = bytes.gread_with::<u16>(offset, scroll::LE)?;
        let minor_version = bytes.gread_with::<u16>(offset, scroll::LE)?;
        let extra_data = bytes.gread_with::<u32>(offset, scroll::LE)?;
        let version_len = bytes.gread_with::<u32>(offset, scroll::LE)?;
        if *offset + version_len as usize > bytes.len() {
            return Err(error::Error::Malformed(format!(
                "StorageSignature version offset ({:#x}) and len ({:#x}) exceeds bytes slice ({:#x})",
                *offset,
                version_len,
                bytes.len()
            )));
        }
        let version = &bytes[*offset..*offset + version_len as usize];
        *offset += version_len as usize;
        Ok(Self {
            signature,
            major_version,
            minor_version,
            extra_data,
            version_len,
            version,
        })
    }

    /// Returns `true` if [`Self::signature`] matches the [`DOTNET_SIGNATURE`], otherwise `false`.
    pub fn is_valid(&self) -> bool {
        self.signature == DOTNET_SIGNATURE
    }

    /// Converts [`StorageSignature::version`] slice into a implicit [`Cow`] if [`StorageSignature::version_len`] is valid
    pub fn to_version_string(&self) -> Option<Cow<'a, str>> {
        self.version_len.is_zero().not().then(|| {
            // Strip null-terminator if any
            self.version
                .strip_suffix(&[0u8])
                .map(String::from_utf8_lossy)
                .unwrap_or_else(|| String::from_utf8_lossy(&self.version))
        })
    }
}

/// Represents the header structure for a storage section in .NET metadata.
/// This structure contains information about the storage's format and the number of streams.
#[repr(C)]
#[derive(PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct StorageHeader {
    /// Indicates the flags for this storage header, defining specific attributes or settings.
    pub flags: u8,
    /// Reserved for future use; should be set to `0`.
    pub reserved: u8,
    /// Indicates the number of streams in this storage header.
    pub streams: u16,
}

impl fmt::Debug for StorageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageHeader")
            .field("flags", &format_args!("{:#x}", &self.flags))
            .field("reserved", &format_args!("{:#x}", &self.reserved))
            .field("streams", &self.streams)
            .finish()
    }
}

/// Represents an individual stream within the .NET storage section, which may contain
/// metadata or other data specific to the .NET assembly structure.
#[derive(PartialEq, Copy, Clone, Default)]
pub struct StorageStream<'a> {
    /// Indicates the offset, in bytes, from the beginning of the file to this stream.
    pub offset: u32,
    /// Indicates the size of this stream, in bytes.
    pub size: u32,
    /// Indicates the name of the stream as a null-terminated ANSI string.
    /// This field can hold up to 32-bytes long, including the null-terminator.
    pub name: &'a [u8],
}

impl fmt::Debug for StorageStream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageStream")
            .field("offset", &format_args!("{:#x}", &self.offset))
            .field("size", &format_args!("{:#x}", &self.size))
            .field("name", &self.to_name_string())
            .field("name_slice", &format_args!("{:02x?}", self.name))
            .finish()
    }
}

impl<'a> StorageStream<'a> {
    pub fn parse(bytes: &'a [u8], offset: &mut usize) -> error::Result<Self> {
        let offset_ = bytes.gread_with::<u32>(offset, scroll::LE)?;
        let size = bytes.gread_with::<u32>(offset, scroll::LE)?;
        let name_size =
            &bytes[*offset..].iter().take_while(|x| *x != &0).count() * core::mem::size_of::<u8>();
        if *offset + name_size as usize + core::mem::size_of::<u8>() > bytes.len() {
            return Err(error::Error::Malformed(format!(
                "StorageStream name offset ({:#x}) and size ({:#x}) exceeds bytes slice ({:#x})",
                *offset,
                name_size,
                bytes.len()
            )));
        }
        let name = &bytes[*offset..*offset + name_size + core::mem::size_of::<u8>()];
        *offset += align_up(name.len(), core::mem::size_of::<u32>());
        Ok(Self {
            offset: offset_,
            size,
            name,
        })
    }

    /// Converts [`StorageStream::name`] slice into a implicit [`Cow`]
    pub fn to_name_string(&self) -> Cow<'a, str> {
        // Strip null-terminator if any
        self.name
            .strip_suffix(&[0u8])
            .map(String::from_utf8_lossy)
            .unwrap_or_else(|| String::from_utf8_lossy(&self.name))
    }
}

/// Iterator over [`StorageStream`] (a CLR section) entries in [`Cor20Header::metadata`].
#[derive(Debug, Copy, Clone)]
pub struct ClrSectionIterator<'a> {
    /// The storage header, used to acquire the number of CLR sections
    pub storage_header: StorageHeader,
    /// The raw data that scoped to the appropriate offset at the end of [`StorageHeader`]
    pub data: &'a [u8],
    /// Internal counter since there are no way to know the size of [`ClrSectionIterator::data`] at the ctor.
    pub(self) index_cursor: usize,
}

impl<'a> ClrSectionIterator<'a> {
    /// Returns the number of CLR sections in this iterator
    pub fn count(&self) -> usize {
        self.storage_header.streams as usize
    }
}

impl<'a> Iterator for ClrSectionIterator<'a> {
    type Item = error::Result<StorageStream<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        // We cannot call `self.count()` here that causes infinite recursive loop
        if self.data.is_empty() || self.index_cursor >= self.storage_header.streams as usize {
            return None;
        }

        let mut offset = 0;
        Some(match StorageStream::parse(self.data, &mut offset) {
            Ok(stream) => {
                debug!("Parsed next CLR section: ({:#x}) {:?}", offset, stream);
                self.data = &self.data[offset..];
                self.index_cursor += 1;
                Ok(stream)
            }
            Err(error) => {
                self.data = &[];
                Err(error.into())
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (
            self.storage_header.streams as usize,
            Some(self.storage_header.streams as usize),
        )
    }
}

impl FusedIterator for ClrSectionIterator<'_> {}

#[cfg(test)]
mod tests {
    use super::{ClrSectionIterator, StorageHeader, StorageStream};

    /// A raw representation of bytes that contains 5 sections.
    const CLR_SECTIONS_VALID: &[u8] = &[
        0x6c, 0x00, 0x00, 0x00, 0xf0, 0x15, 0x0d, 0x00, 0x23, 0x7e, 0x00, 0x00, 0x5c, 0x16, 0x0d,
        0x00, 0x34, 0x23, 0x04, 0x00, 0x23, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x00,
        0x00, 0x00, 0x90, 0x39, 0x11, 0x00, 0x38, 0xb9, 0x04, 0x00, 0x23, 0x55, 0x53, 0x00, 0xc8,
        0xf2, 0x15, 0x00, 0x10, 0x00, 0x00, 0x00, 0x23, 0x47, 0x55, 0x49, 0x44, 0x00, 0x00, 0x00,
        0xd8, 0xf2, 0x15, 0x00, 0xfc, 0x12, 0x02, 0x00, 0x23, 0x42, 0x6c, 0x6f, 0x62, 0x00, 0x00,
        0x00,
    ];

    #[test]
    fn parse_clr_sections() {
        let storage_header = StorageHeader {
            flags: 0,
            reserved: 0,
            streams: 5,
        };
        let it = ClrSectionIterator {
            storage_header,
            data: &CLR_SECTIONS_VALID,
            index_cursor: 0,
        };
        let it_vec = it.collect::<Result<Vec<_>, _>>();
        assert_eq!(it_vec.is_ok(), true);
        let it_vec = it_vec.unwrap();
        assert_eq!(it_vec.len(), it.count());

        let at_0 = it_vec.get(0).map(|x| *x);
        assert_eq!(
            at_0,
            Some(StorageStream {
                offset: 0x6c,
                size: 0xd15f0,
                name: b"#~\0"
            })
        );
        assert_eq!(at_0.unwrap().to_name_string(), "#~");

        let at_1 = it_vec.get(1).map(|x| *x);
        assert_eq!(
            at_1,
            Some(StorageStream {
                offset: 0xd165c,
                size: 0x42334,
                name: b"#Strings\0"
            })
        );
        assert_eq!(at_1.unwrap().to_name_string(), "#Strings");

        let at_2 = it_vec.get(2).map(|x| *x);
        assert_eq!(
            at_2,
            Some(StorageStream {
                offset: 0x113990,
                size: 0x4b938,
                name: b"#US\0"
            })
        );
        assert_eq!(at_2.unwrap().to_name_string(), "#US");

        let at_3 = it_vec.get(3).map(|x| *x);
        assert_eq!(
            at_3,
            Some(StorageStream {
                offset: 0x15f2c8,
                size: 0x10,
                name: b"#GUID\0"
            })
        );
        assert_eq!(at_3.unwrap().to_name_string(), "#GUID");

        let at_4 = it_vec.get(4).map(|x| *x);
        assert_eq!(
            at_4,
            Some(StorageStream {
                offset: 0x15f2d8,
                size: 0x212fc,
                name: b"#Blob\0"
            })
        );
        assert_eq!(at_4.unwrap().to_name_string(), "#Blob");

        let at_5 = it_vec.get(5);
        assert_eq!(at_5, None);
    }
}
