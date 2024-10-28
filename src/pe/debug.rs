use core::iter::FusedIterator;

use crate::error;
use alloc::vec::Vec;
use log::debug;
use scroll::{Pread, Pwrite, SizeWith};

use crate::pe::data_directories;
use crate::pe::options;
use crate::pe::section_table;
use crate::pe::utils;

/// Size of [`ImageDebugDirectory`]
pub const IMAGE_DEBUG_DIRECTORY_SIZE: usize = 0x1C;

/// Iterator over debug directory entries in [`DebugData`].
#[derive(Debug, Copy, Clone)]
pub struct ImageDebugDirectoryIterator<'a> {
    /// Raw data reference that scoped to the next element if appropriate
    data: &'a [u8],
    /// Fixup RVA offset used for TE fixups
    ///
    /// - **When zero**: no fixup is performed
    /// - **When non-zero**: fixup is performed
    rva_offset: u32,
}

impl Iterator for ImageDebugDirectoryIterator<'_> {
    type Item = error::Result<ImageDebugDirectory>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        Some(
            match self.data.pread_with::<ImageDebugDirectory>(0, scroll::LE) {
                Ok(func) => {
                    self.data = &self.data[IMAGE_DEBUG_DIRECTORY_SIZE..];

                    // Adjust all addresses in the TE binary debug data if fixup is specified
                    let idd = ImageDebugDirectory {
                        address_of_raw_data: func.address_of_raw_data.wrapping_sub(self.rva_offset),
                        pointer_to_raw_data: func.pointer_to_raw_data.wrapping_sub(self.rva_offset),
                        ..func
                    };

                    debug!(
                        "ImageDebugDirectory address of raw data fixed up from: 0x{:X} to 0x{:X}",
                        idd.address_of_raw_data.wrapping_add(self.rva_offset),
                        idd.address_of_raw_data,
                    );

                    debug!(
                        "ImageDebugDirectory pointer to raw data fixed up from: 0x{:X} to 0x{:X}",
                        idd.pointer_to_raw_data.wrapping_add(self.rva_offset),
                        idd.pointer_to_raw_data,
                    );

                    Ok(idd)
                }
                Err(error) => {
                    self.data = &[];
                    Err(error.into())
                }
            },
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.data.len() / IMAGE_DEBUG_DIRECTORY_SIZE;
        (len, Some(len))
    }
}

impl FusedIterator for ImageDebugDirectoryIterator<'_> {}
impl ExactSizeIterator for ImageDebugDirectoryIterator<'_> {}

/// Represents debug data extracted from a PE (Portable Executable) or TE (Terse Executable) file.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct DebugData<'a> {
    /// Raw data covering bytes of entire [`ImageDebugDirectory`]
    pub data: &'a [u8],
    /// Fixup RVA offset used for TE fixups
    ///
    /// - **When zero**: no fixup is performed
    /// - **When non-zero**: fixup is performed
    pub rva_offset: u32,
    /// Parsed CodeView PDB 7.0 (RSDS) debug information, if available.
    ///
    /// CodeView PDB 7.0 contains a GUID, an age value, and the path to the PDB file.
    /// This is commonly used in modern PDB files.
    ///
    /// [`IMAGE_DEBUG_TYPE_CODEVIEW`]
    pub codeview_pdb70_debug_info: Option<CodeviewPDB70DebugInfo<'a>>,
    /// Parsed CodeView PDB 2.0 (NB10) debug information, if available.
    ///
    /// CodeView PDB 2.0 includes a signature, an age value, and the path to the PDB file.
    /// It is used in older PDB formats.
    ///
    /// [`IMAGE_DEBUG_TYPE_CODEVIEW`]
    pub codeview_pdb20_debug_info: Option<CodeviewPDB20DebugInfo<'a>>,
    /// Visual C++ feature data, if available.
    ///
    /// This includes information about specific features or optimizations enabled
    /// in Visual C++ builds.
    ///
    /// [`IMAGE_DEBUG_TYPE_VC_FEATURE`]
    pub vcfeature_info: Option<VCFeatureInfo>,
    /// Extended DLL characteristics information, if available.
    ///
    /// This data includes extended properties of the DLL that may affect
    /// how the operating system handles the DLL, such as security features.
    ///
    /// [`IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS`]
    pub ex_dll_characteristics_info: Option<ExDllCharacteristicsInfo>,
    /// Reproducible build (Repro) information, if available.
    ///
    /// - **MSVC builds**: Contains a 32-byte hash stored directly in the raw data.
    /// - **Clang builds**: Uses the [`ImageDebugDirectory::time_date_stamp`] as a hash,
    ///   with no dedicated raw data.
    ///
    /// [`IMAGE_DEBUG_TYPE_REPRO`]
    pub repro_info: Option<ReproInfo<'a>>,
}

impl<'a> DebugData<'a> {
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
        Self::parse_with_opts_and_fixup(bytes, dd, sections, file_alignment, opts, 0)
    }

    pub fn parse_with_opts_and_fixup(
        bytes: &'a [u8],
        dd: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        opts: &options::ParseOptions,
        rva_offset: u32,
    ) -> error::Result<Self> {
        let offset =
            utils::find_offset(dd.virtual_address as usize, sections, file_alignment, opts)
                .ok_or_else(|| {
                    error::Error::Malformed(format!(
                        "Cannot map ImageDebugDirectory rva {:#x} into offset",
                        dd.virtual_address
                    ))
                })?;

        // Ensure that the offset and size do not exceed the length of the bytes slice
        if offset + dd.size as usize > bytes.len() {
            return Err(error::Error::Malformed(format!(
                "ImageDebugDirectory offset {:#x} and size {:#x} exceeds the bounds of the bytes size {:#x}",
                offset, dd.size, bytes.len()
            )));
        }
        let data = &bytes[offset..offset + dd.size as usize];
        let iterator = ImageDebugDirectoryIterator { data, rva_offset };

        let codeview_pdb70_debug_info =
            CodeviewPDB70DebugInfo::parse_with_opts(bytes, iterator, opts)?;
        let codeview_pdb20_debug_info =
            CodeviewPDB20DebugInfo::parse_with_opts(bytes, iterator, opts)?;
        let vcfeature_info = VCFeatureInfo::parse_with_opts(bytes, iterator, opts)?;
        let ex_dll_characteristics_info =
            ExDllCharacteristicsInfo::parse_with_opts(bytes, iterator, opts)?;
        let repro_info = ReproInfo::parse_with_opts(bytes, iterator, opts)?;

        Ok(DebugData {
            data,
            rva_offset,
            codeview_pdb70_debug_info,
            codeview_pdb20_debug_info,
            vcfeature_info,
            ex_dll_characteristics_info,
            repro_info,
        })
    }

    /// Return this executable's debugging GUID, suitable for matching against a PDB file.
    pub fn guid(&self) -> Option<[u8; 16]> {
        self.codeview_pdb70_debug_info.map(|pdb70| pdb70.signature)
    }

    /// Find a specific debug type in the debug data.
    pub fn find_type(&self, data_type: u32) -> Option<ImageDebugDirectory> {
        self.entries()
            .filter_map(Result::ok)
            .find(|idd| idd.data_type == data_type)
    }

    /// Returns iterator for [`ImageDebugDirectory`]
    pub fn entries(&self) -> ImageDebugDirectoryIterator<'a> {
        ImageDebugDirectoryIterator {
            data: &self.data,
            rva_offset: self.rva_offset,
        }
    }
}

/// Represents the IMAGE_DEBUG_DIRECTORY structure in a Portable Executable (PE) file.
///
/// This structure holds information about the debug data in a PE file. It is used
/// to locate debug information such as PDB files or other types of debugging data.
/// The fields correspond to the Windows-specific IMAGE_DEBUG_DIRECTORY structure.
///
/// For more details, see the [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#image-debug_directory).
///
/// <https://msdn.microsoft.com/en-us/library/windows/desktop/ms680307(v=vs.85).aspx>
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct ImageDebugDirectory {
    /// The characteristics of the debug data, reserved for future use.
    pub characteristics: u32,
    /// The time and date when the debug data was created, represented as a Unix timestamp.
    pub time_date_stamp: u32,
    /// The major version number of the debug data format.
    pub major_version: u16,
    /// The minor version number of the debug data format.
    pub minor_version: u16,
    /// The type of debug data, such as codeview or coff.
    pub data_type: u32,
    /// The size of the debug data in bytes.
    pub size_of_data: u32,
    /// The address of the debug data when loaded into memory.
    pub address_of_raw_data: u32,
    /// The file pointer to the debug data within the PE file.
    pub pointer_to_raw_data: u32,
}

/// Represents an unknown debug data type.
pub const IMAGE_DEBUG_TYPE_UNKNOWN: u32 = 0;
/// Represents COFF (Common Object File Format) debug information.
pub const IMAGE_DEBUG_TYPE_COFF: u32 = 1;
/// Represents CodeView debug information, often used for PDB (Program Database) files.
pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
/// Represents FPO (Frame Pointer Omission) information.
pub const IMAGE_DEBUG_TYPE_FPO: u32 = 3;
/// Represents miscellaneous debug information.
pub const IMAGE_DEBUG_TYPE_MISC: u32 = 4;
/// Represents exception handling information.
pub const IMAGE_DEBUG_TYPE_EXCEPTION: u32 = 5;
/// Represents fixup information, used for relocation.
pub const IMAGE_DEBUG_TYPE_FIXUP: u32 = 6;
/// Represents OMAP (Optimized Map) information from source to compiled addresses.
pub const IMAGE_DEBUG_TYPE_OMAP_TO_SRC: u32 = 7;
/// Represents OMAP information from compiled addresses to source.
pub const IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: u32 = 8;
/// Represents Borland-specific debug information.
pub const IMAGE_DEBUG_TYPE_BORLAND: u32 = 9;
/// Reserved debug data type (value 10).
pub const IMAGE_DEBUG_TYPE_RESERVED10: u32 = 10;
/// Represents BBT (Basic Block Transfer) information, an alias for reserved type 10.
pub const IMAGE_DEBUG_TYPE_BBT: u32 = IMAGE_DEBUG_TYPE_RESERVED10;
/// Represents a CLSID (Class ID) associated with the debug data.
pub const IMAGE_DEBUG_TYPE_CLSID: u32 = 11;
/// Represents Visual C++ feature data.
pub const IMAGE_DEBUG_TYPE_VC_FEATURE: u32 = 12;
/// Represents POGO (Profile Guided Optimization) information.
pub const IMAGE_DEBUG_TYPE_POGO: u32 = 13;
/// Represents ILTCG (Intermediate Language to Code Generation) optimization data.
pub const IMAGE_DEBUG_TYPE_ILTCG: u32 = 14;
/// Represents MPX (Memory Protection Extensions) related debug information.
pub const IMAGE_DEBUG_TYPE_MPX: u32 = 15;
/// Represents repro information, typically used for reproducible builds.
pub const IMAGE_DEBUG_TYPE_REPRO: u32 = 16;
/// Represents an embedded Portable PDB, a .NET-specific debug information format.
pub const IMAGE_DEBUG_TYPE_EMBEDDEDPORTABLEPDB: u32 = 17;
/// Represents SPGO (Static Profile Guided Optimization) information.
pub const IMAGE_DEBUG_TYPE_SPGO: u32 = 18;
/// Represents a checksum for the PDB file.
pub const IMAGE_DEBUG_TYPE_PDBCHECKSUM: u32 = 19;
/// Represents extended DLL characteristics for debugging.
pub const IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: u32 = 20;
/// Represents a performance map for profiling.
pub const IMAGE_DEBUG_TYPE_PERFMAP: u32 = 21;

/// Magic number for CodeView PDB 7.0 signature (`'SDSR'`).
pub const CODEVIEW_PDB70_MAGIC: u32 = 0x5344_5352;
/// Magic number for CodeView PDB 2.0 signature (`'01BN'`).
pub const CODEVIEW_PDB20_MAGIC: u32 = 0x3031_424e;
/// Magic number for CodeView CV 5.0 signature (`'11BN'`).
pub const CODEVIEW_CV50_MAGIC: u32 = 0x3131_424e;
/// Magic number for CodeView CV 4.1 signature (`'90BN'`).
pub const CODEVIEW_CV41_MAGIC: u32 = 0x3930_424e;

// http://llvm.org/doxygen/CVDebugRecord_8h_source.html
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct CodeviewPDB70DebugInfo<'a> {
    pub codeview_signature: u32,
    pub signature: [u8; 16],
    pub age: u32,
    pub filename: &'a [u8],
}

impl<'a> CodeviewPDB70DebugInfo<'a> {
    pub fn parse(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
    ) -> error::Result<Option<Self>> {
        Self::parse_with_opts(bytes, idd, &options::ParseOptions::default())
    }

    pub fn parse_with_opts(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
        opts: &options::ParseOptions,
    ) -> error::Result<Option<Self>> {
        let idd = idd.collect::<Result<Vec<_>, _>>()?;
        let idd = idd
            .iter()
            .find(|idd| idd.data_type == IMAGE_DEBUG_TYPE_CODEVIEW);

        if let Some(idd) = idd {
            // ImageDebugDirectory.pointer_to_raw_data stores a raw offset -- not a virtual offset -- which we can use directly
            let mut offset: usize = match opts.resolve_rva {
                true => idd.pointer_to_raw_data as usize,
                false => idd.address_of_raw_data as usize,
            };

            // calculate how long the eventual filename will be, which doubles as a check of the record size
            let filename_length = idd.size_of_data as isize - 24;
            if filename_length < 0 {
                // the record is too short to be plausible
                return Err(error::Error::Malformed(format!(
                    "ImageDebugDirectory size of data seems wrong: {:?}",
                    idd.size_of_data
                )));
            }
            let filename_length = filename_length as usize;

            // check the codeview signature
            let codeview_signature: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
            if codeview_signature != CODEVIEW_PDB70_MAGIC {
                return Ok(None);
            }

            // read the rest
            let mut signature: [u8; 16] = [0; 16];
            signature.copy_from_slice(bytes.gread_with(&mut offset, 16)?);
            let age: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
            if let Some(filename) = bytes.get(offset..offset + filename_length) {
                Ok(Some(CodeviewPDB70DebugInfo {
                    codeview_signature,
                    signature,
                    age,
                    filename,
                }))
            } else {
                Err(error::Error::Malformed(format!(
                    "ImageDebugDirectory seems corrupted: {:?}",
                    idd
                )))
            }
        } else {
            // CodeView debug info not found
            Ok(None)
        }
    }
}

/// Represents the `IMAGE_DEBUG_VC_FEATURE_ENTRY` structure
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct VCFeatureInfo {
    /// The count of pre-VC++
    pub pre_vc_plusplus_count: u32,
    /// The count of C and C++
    pub c_and_cplusplus_count: u32,
    /// The count of guard stack
    pub guard_stack_count: u32,
    /// The count of SDL
    pub sdl_count: u32,
    /// The count of guard
    pub guard_count: u32,
}

impl<'a> VCFeatureInfo {
    pub fn parse(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
    ) -> error::Result<Option<Self>> {
        Self::parse_with_opts(bytes, idd, &options::ParseOptions::default())
    }

    pub fn parse_with_opts(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
        opts: &options::ParseOptions,
    ) -> error::Result<Option<Self>> {
        let idd = idd.collect::<Result<Vec<_>, _>>()?;
        let idd = idd
            .iter()
            .find(|idd| idd.data_type == IMAGE_DEBUG_TYPE_VC_FEATURE);

        if let Some(idd) = idd {
            let mut offset: usize = match opts.resolve_rva {
                true => idd.pointer_to_raw_data as usize,
                false => idd.address_of_raw_data as usize,
            };

            let pre_vc_plusplus_count: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
            let c_and_cplusplus_count: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
            let guard_stack_count: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
            let sdl_count: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
            let guard_count: u32 = bytes.gread_with(&mut offset, scroll::LE)?;

            Ok(Some(VCFeatureInfo {
                pre_vc_plusplus_count,
                c_and_cplusplus_count,
                guard_stack_count,
                sdl_count,
                guard_count,
            }))
        } else {
            // VC Feature info not found
            return Ok(None);
        }
    }
}

// http://llvm.org/doxygen/CVDebugRecord_8h_source.html
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct CodeviewPDB20DebugInfo<'a> {
    pub codeview_signature: u32,
    pub codeview_offset: u32,
    pub signature: u32,
    pub age: u32,
    pub filename: &'a [u8],
}

impl<'a> CodeviewPDB20DebugInfo<'a> {
    pub fn parse(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
    ) -> error::Result<Option<Self>> {
        Self::parse_with_opts(bytes, idd, &options::ParseOptions::default())
    }

    pub fn parse_with_opts(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
        opts: &options::ParseOptions,
    ) -> error::Result<Option<Self>> {
        let idd = idd.collect::<Result<Vec<_>, _>>()?;
        let idd = idd
            .iter()
            .find(|idd| idd.data_type == IMAGE_DEBUG_TYPE_CODEVIEW);

        if let Some(idd) = idd {
            // ImageDebugDirectory.pointer_to_raw_data stores a raw offset -- not a virtual offset -- which we can use directly
            let mut offset: usize = match opts.resolve_rva {
                true => idd.pointer_to_raw_data as usize,
                false => idd.address_of_raw_data as usize,
            };

            // calculate how long the eventual filename will be, which doubles as a check of the record size
            let filename_length = idd.size_of_data as isize - 16;
            if filename_length < 0 {
                // the record is too short to be plausible
                return Err(error::Error::Malformed(format!(
                    "ImageDebugDirectory size of data seems wrong: {:?}",
                    idd.size_of_data
                )));
            }
            let filename_length = filename_length as usize;

            // check the codeview signature
            let codeview_signature: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
            if codeview_signature != CODEVIEW_PDB20_MAGIC {
                return Ok(None);
            }
            let codeview_offset: u32 = bytes.gread_with(&mut offset, scroll::LE)?;

            // read the rest
            let signature: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
            let age: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
            if let Some(filename) = bytes.get(offset..offset + filename_length) {
                Ok(Some(CodeviewPDB20DebugInfo {
                    codeview_signature,
                    codeview_offset,
                    signature,
                    age,
                    filename,
                }))
            } else {
                Err(error::Error::Malformed(format!(
                    "ImageDebugDirectory seems corrupted: {:?}",
                    idd
                )))
            }
        } else {
            // Codeview20 not found
            return Ok(None);
        }
    }
}

/// Represents the reproducible build (Repro) information extracted from a PE (Portable Executable) file.
///
/// The Repro information differs based on the compiler used to build the executable:
/// - For MSVC (Microsoft Visual C++), the Repro information is written directly into the raw data as a 32-byte hash.
/// - For Clang/(correctly, LLD linker), there is no dedicated raw data for the Repro information. Instead, the [`ImageDebugDirectory::time_date_stamp`]
///   field functions as a hash, providing a unique identifier for the reproducible build.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ReproInfo<'a> {
    /// Represents a hash stored in the [`ImageDebugDirectory::time_date_stamp`] field.
    ///
    /// This variant is used primarily for executables built with Clang/LLD, where the
    /// [`ImageDebugDirectory::time_date_stamp`] acts as the Repro hash.
    TimeDateStamp(u32),
    /// Represents a buffer containing the 32-byte Repro hash.
    ///
    /// This variant is used for MSVC-built executables, where the Repro hash is directly
    /// stored as raw data in the debug directory.
    Buffer {
        /// The length of the buffer containing the Repro data. For MSVC, this is typically 32 bytes long.
        length: u32,
        /// A reference to the buffer containing the Repro hash data.
        buffer: &'a [u8],
    },
}

impl<'a> ReproInfo<'a> {
    pub fn parse(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
    ) -> error::Result<Option<Self>> {
        Self::parse_with_opts(bytes, idd, &options::ParseOptions::default())
    }

    pub fn parse_with_opts(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
        opts: &options::ParseOptions,
    ) -> error::Result<Option<Self>> {
        let idd = idd.collect::<Result<Vec<_>, _>>()?;
        let idd = idd
            .iter()
            .find(|idd| idd.data_type == IMAGE_DEBUG_TYPE_REPRO);

        if let Some(idd) = idd {
            let mut offset: usize = match opts.resolve_rva {
                true => idd.pointer_to_raw_data as usize,
                false => idd.address_of_raw_data as usize,
            };

            // Clang(LLD) produces no data, uses timestamp field instead
            // MSVC(link.exe) produces 32-byte data
            if idd.size_of_data > 0 {
                let length: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
                if let Some(buffer) = bytes.get(offset..offset + length as usize) {
                    Ok(Some(Self::Buffer { length, buffer }))
                } else {
                    Err(error::Error::Malformed(format!(
                        "ImageDebugDirectory seems corrupted: {:?}",
                        idd
                    )))
                }
            } else {
                Ok(Some(Self::TimeDateStamp(idd.time_date_stamp)))
            }
        } else {
            return Ok(None);
        }
    }
}

/// Represents extended DLL characteristics information.
///
/// This structure holds additional characteristics of a DLL that may influence
/// how the operating system loads or manages the DLL, especially in terms of
/// security features and optimizations. These characteristics can include
/// settings related to Intel CET (Control-flow Enforcement Technology) and other
/// security-relevant attributes.
#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct ExDllCharacteristicsInfo {
    /// The extended characteristics of the DLL.
    ///
    /// This field is a bitmask of flags that define various security and performance
    /// properties of the DLL. The specific flags are defined by the PE format specification.
    ///
    /// This field contains one or more bitflags of:
    ///
    /// - [`IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT`]
    /// - [`IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE`]
    /// - [`IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE`]
    /// - [`IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC_ONLY`]
    /// - [`IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_1`]
    /// - [`IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_2`]
    pub characteristics_ex: u32,
}

/// Indicates that Control Flow Enforcement Technology (CET) is enabled for the DLL,
/// enhancing security via control-flow integrity.
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT: u32 = 0x1;
/// Indicates that CET is enforced in strict mode, increasing security measures against
/// control-flow attacks but may impact compatibility.
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE: u32 = 0x2;
/// Indicates that relaxed mode for Context IP Validation under CET is allowed,
/// providing a balance between security and performance.
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE: u32 = 0x4;
/// Indicates that the use of dynamic APIs is restricted to processes only,
/// enhancing security by limiting external API calls under CET.
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC_ONLY: u32 = 0x8;
/// Reserved for future.
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_1: u32 = 0x10;
/// Reserved for future.
pub const IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_2: u32 = 0x20;
/// Indicates that the DLL is compatible with Forward Control Flow Integrity (CFI).
///
/// This flag signifies that the DLL is designed to support forward CFI, a security
/// feature that helps prevent certain types of control flow attacks by ensuring
/// that control flow transfers occur only to valid targets.
pub const IMAGE_DLLCHARACTERISTICS_EX_FORWARD_CFI_COMPAT: u32 = 0x40;
/// Indicates that the DLL is hotpatch-compatible.
///
/// This flag indicates that the DLL can be modified while in use (hotpatching),
/// allowing updates or fixes to be applied without needing to restart the application
/// or service that is using the DLL. This can be useful for maintaining uptime and
/// applying critical patches in a live environment.
pub const IMAGE_DLLCHARACTERISTICS_EX_HOTPATCH_COMPATIBLE: u32 = 0x80;

impl<'a> ExDllCharacteristicsInfo {
    pub fn parse(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
    ) -> error::Result<Option<Self>> {
        Self::parse_with_opts(bytes, idd, &options::ParseOptions::default())
    }

    pub fn parse_with_opts(
        bytes: &'a [u8],
        idd: ImageDebugDirectoryIterator<'_>,
        opts: &options::ParseOptions,
    ) -> error::Result<Option<Self>> {
        let idd = idd.collect::<Result<Vec<_>, _>>()?;
        let idd = idd
            .iter()
            .find(|idd| idd.data_type == IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS);

        if let Some(idd) = idd {
            // ImageDebugDirectory.pointer_to_raw_data stores a raw offset -- not a virtual offset -- which we can use directly
            let mut offset: usize = match opts.resolve_rva {
                true => idd.pointer_to_raw_data as usize,
                false => idd.address_of_raw_data as usize,
            };

            let characteristics_ex: u32 = bytes.gread_with(&mut offset, scroll::LE)?;

            Ok(Some(ExDllCharacteristicsInfo { characteristics_ex }))
        } else {
            return Ok(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExDllCharacteristicsInfo, ImageDebugDirectory, ReproInfo, VCFeatureInfo,
        IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS, IMAGE_DEBUG_TYPE_ILTCG,
        IMAGE_DEBUG_TYPE_POGO, IMAGE_DEBUG_TYPE_REPRO, IMAGE_DEBUG_TYPE_VC_FEATURE,
        IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT, IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE,
    };

    const DEBUG_DIRECTORIES_TEST_MSVC_BIN: &[u8] =
        include_bytes!("../../tests/bins/pe/debug_directories-msvc.exe.bin");
    const DEBUG_DIRECTORIES_TEST_CLANG_LLD_BIN: &[u8] =
        include_bytes!("../../tests/bins/pe/debug_directories-clang_lld.exe.bin");

    #[test]
    fn parse_debug_entries_iterator() {
        let binary =
            crate::pe::PE::parse(DEBUG_DIRECTORIES_TEST_MSVC_BIN).expect("Unable to parse binary");
        assert_eq!(binary.debug_data.is_some(), true);
        let debug_data = binary.debug_data.unwrap();
        let entries = debug_data.entries().collect::<Result<Vec<_>, _>>();
        assert_eq!(entries.is_ok(), true);
        let entries = entries.unwrap();
        let entries_expect = vec![
            ImageDebugDirectory {
                characteristics: 0x0,
                time_date_stamp: 0x80AC7661,
                major_version: 0x0,
                minor_version: 0x0,
                data_type: IMAGE_DEBUG_TYPE_CODEVIEW,
                size_of_data: 0x38,
                address_of_raw_data: 0x20c0,
                pointer_to_raw_data: 0x4c0,
            },
            ImageDebugDirectory {
                characteristics: 0x0,
                time_date_stamp: 0x80AC7661,
                major_version: 0x0,
                minor_version: 0x0,
                data_type: IMAGE_DEBUG_TYPE_VC_FEATURE,
                size_of_data: 0x14,
                address_of_raw_data: 0x20f8,
                pointer_to_raw_data: 0x4f8,
            },
            ImageDebugDirectory {
                characteristics: 0x0,
                time_date_stamp: 0x80AC7661,
                major_version: 0x0,
                minor_version: 0x0,
                data_type: IMAGE_DEBUG_TYPE_POGO,
                size_of_data: 0x58,
                address_of_raw_data: 0x210c,
                pointer_to_raw_data: 0x50c,
            },
            ImageDebugDirectory {
                characteristics: 0x0,
                time_date_stamp: 0x80AC7661,
                major_version: 0x0,
                minor_version: 0x0,
                data_type: IMAGE_DEBUG_TYPE_ILTCG,
                size_of_data: 0x0,
                address_of_raw_data: 0x0,
                pointer_to_raw_data: 0x0,
            },
            ImageDebugDirectory {
                characteristics: 0x0,
                time_date_stamp: 0x80AC7661,
                major_version: 0x0,
                minor_version: 0x0,
                data_type: IMAGE_DEBUG_TYPE_REPRO,
                size_of_data: 0x24,
                address_of_raw_data: 0x2164,
                pointer_to_raw_data: 0x564,
            },
            ImageDebugDirectory {
                characteristics: 0x0,
                time_date_stamp: 0x80AC7661,
                major_version: 0x0,
                minor_version: 0x0,
                data_type: IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS,
                size_of_data: 0x4,
                address_of_raw_data: 0x2188,
                pointer_to_raw_data: 0x588,
            },
        ];
        assert_eq!(entries, entries_expect);
    }

    #[test]
    fn parse_debug_vcfeature() {
        let binary =
            crate::pe::PE::parse(DEBUG_DIRECTORIES_TEST_MSVC_BIN).expect("Unable to parse binary");
        assert_eq!(binary.debug_data.is_some(), true);
        let debug_data = binary.debug_data.unwrap();
        assert_eq!(debug_data.vcfeature_info.is_some(), true);
        let vcfeature_info = debug_data.vcfeature_info.unwrap();
        let vcfeature_info_expect = VCFeatureInfo {
            pre_vc_plusplus_count: 0,
            c_and_cplusplus_count: 1,
            guard_stack_count: 0,
            sdl_count: 0,
            guard_count: 0,
        };
        assert_eq!(vcfeature_info, vcfeature_info_expect);
    }

    #[test]
    fn parse_debug_repro_msvc() {
        let binary =
            crate::pe::PE::parse(DEBUG_DIRECTORIES_TEST_MSVC_BIN).expect("Unable to parse binary");
        assert_eq!(binary.debug_data.is_some(), true);
        let debug_data = binary.debug_data.unwrap();
        assert_eq!(debug_data.repro_info.is_some(), true);
        let repro_info = debug_data.repro_info.unwrap();
        let repro_info_expect = ReproInfo::Buffer {
            length: 32,
            buffer: &[
                0x1F, 0x4F, 0x58, 0x9C, 0x3C, 0xEA, 0x00, 0x83, 0x3F, 0x57, 0x00, 0xCC, 0x36, 0xA7,
                0x84, 0xDF, 0xF7, 0x7C, 0x70, 0xE0, 0xEF, 0x7A, 0xBA, 0x08, 0xD0, 0xA6, 0x8B, 0x7F,
                0x61, 0x76, 0xAC, 0x80,
            ],
        };
        assert_eq!(repro_info, repro_info_expect);
    }

    #[test]
    fn parse_debug_repro_clang_lld() {
        let binary = crate::pe::PE::parse(DEBUG_DIRECTORIES_TEST_CLANG_LLD_BIN)
            .expect("Unable to parse binary");
        assert_eq!(binary.debug_data.is_some(), true);
        let debug_data = binary.debug_data.unwrap();
        assert_eq!(debug_data.repro_info.is_some(), true);
        let repro_info = debug_data.repro_info.unwrap();
        let repro_info_expect = ReproInfo::TimeDateStamp(0xDB2F3908);
        assert_eq!(repro_info, repro_info_expect);
    }

    #[test]
    fn parse_debug_exdllcharacteristics() {
        let binary =
            crate::pe::PE::parse(DEBUG_DIRECTORIES_TEST_MSVC_BIN).expect("Unable to parse binary");
        assert_eq!(binary.debug_data.is_some(), true);
        let debug_data = binary.debug_data.unwrap();
        assert_eq!(debug_data.ex_dll_characteristics_info.is_some(), true);
        let ex_dll_characteristics_info = debug_data.ex_dll_characteristics_info.unwrap();
        let ex_dll_characteristics_info_expect = ExDllCharacteristicsInfo {
            characteristics_ex: IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
                | IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE,
        };
        assert_eq!(
            ex_dll_characteristics_info,
            ex_dll_characteristics_info_expect
        );
    }
}
