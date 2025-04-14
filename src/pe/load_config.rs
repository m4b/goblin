use core::mem::offset_of;

use scroll::{Pread, Pwrite, SizeWith};

use crate::error;
use crate::pe::data_directories;
use crate::pe::options;
use crate::pe::section_table;
use crate::pe::utils;

// GuardFlags: bitflags for LoadConfigDirectory::guard_flags.

/// Indicate that the module performs control flow integrity checks using system-supplied support.
pub const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
/// Indicate that the module performs control flow and write integrity checks.
pub const IMAGE_GUARD_CFW_INSTRUMENTED: u32 = 0x0000_0200;
/// Indicate that the module contains valid control flow target metadata.
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
/// Indicate that the module does not make use of the /GS security cookie.
pub const IMAGE_GUARD_SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
/// Indicate that the module supports read-only delay load IAT.
pub const IMAGE_GUARD_PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
/// Indicate that the delay-load import table is in its own .didat section that can be freely reprotected.
pub const IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
/// Indicate that the module contains suppressed export information and the address-taken IAT table is present.
pub const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
/// Indicate that the module enables suppression of exports.
pub const IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_8000;
/// Indicate that the module contains longjmp target information.
pub const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
/// Indicate that the module contains return flow instrumentation and metadata.
pub const IMAGE_GUARD_RF_INSTRUMENTED: u32 = 0x0002_0000;
/// Indicate that the module requests the OS to enable return flow protection.
pub const IMAGE_GUARD_RF_ENABLE: u32 = 0x0004_0000;
/// Indicate that the module requests the OS to enable return flow protection in strict mode.
pub const IMAGE_GUARD_RF_STRICT: u32 = 0x0008_0000;
/// Indicate that the module was built with retpoline support.
pub const IMAGE_GUARD_RETPOLINE_PRESENT: u32 = 0x0010_0000;
/// Indicate that the module contains EH continuation target information.
pub const IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
/// Indicate that the module was built with XFG (Cross Function Guard), now deprecated.
pub const IMAGE_GUARD_XFG_ENABLED: u32 = 0x0080_0000;
/// Indicate that the module has CastGuard instrumentation present.
pub const IMAGE_GUARD_CASTGUARD_PRESENT: u32 = 0x0100_0000;
/// Indicate that the module has Guarded Memcpy instrumentation present.
pub const IMAGE_GUARD_MEMCPY_PRESENT: u32 = 0x0200_0000;

// DependentLoadFlags: bitflags for LoadConfigDirectory::dependent_load_flags.

/// Indicate that the system does not resolve DLL references for the loaded module.
pub const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x0000_0001;
/// Indicate that the DLL is loaded as a data file.
pub const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x0000_0002;
/// Indicate that the DLL is loaded as a packaged library.
pub const LOAD_PACKAGED_LIBRARY: u32 = 0x0000_0004;
/// Indicate that the DLL is loaded with an altered search path.
pub const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;
/// Indicate that the system ignores the code authorization level.
pub const LOAD_IGNORE_CODE_AUTHZ_LEVEL: u32 = 0x0000_0010;
/// Indicate that the DLL is loaded as an image resource.
pub const LOAD_LIBRARY_AS_IMAGE_RESOURCE: u32 = 0x0000_0020;
/// Indicate that the DLL is loaded as a data file and cannot be loaded again as an executable.
pub const LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE: u32 = 0x0000_0040;
/// Indicate that the DLL target must be signed.
pub const LOAD_LIBRARY_REQUIRE_SIGNED_TARGET: u32 = 0x0000_0080;
/// Indicate that the system searches the directory that contains the DLL being loaded.
pub const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
/// Indicate that the system searches the application directory.
pub const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x0000_0200;
/// Indicate that the system searches directories added with `AddDllDirectory`.
pub const LOAD_LIBRARY_SEARCH_USER_DIRS: u32 = 0x0000_0400;
/// Indicate that the system searches the System32 directory.
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
/// Indicate that the system uses the default DLL search directories.
pub const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
/// Indicate that the current directory is searched only when it is safe to do so.
pub const LOAD_LIBRARY_SAFE_CURRENT_DIRS: u32 = 0x0000_2000;
/// Indicate that the system searches System32 without resolving forwarded exports.
///
/// This value may not be supported on older versions of Windows.
pub const LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER: u32 = 0x0000_4000;
/// Indicate that the system uses OS integrity continuity policies when loading the DLL.
pub const LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY: u32 = 0x0000_8000;

/// Represents the 64-bit Load Configuration directory structure of a PE file.
///
/// This structure contains information related to the loading configuration
/// of a PE (Portable Executable) file. It provides details for various
/// configuration settings that the operating system loader may use when loading
/// the PE file into memory. This structure is marked as non_exhaustive, meaning
/// that future versions of the PE format may include additional fields that are
/// not present in the current version of this structure.
///
/// # Notes
///
/// This structure may grow in future versions of the PE format, so be cautious
/// when working with it, as some fields may not be available or relevant for
/// all versions of PE files.
#[repr(C)]
#[non_exhaustive]
#[derive(Debug, Clone, Pread, Pwrite, SizeWith, Eq, PartialEq)]
pub struct LoadConfigDirectory64 {
    /// The size of the structure.
    pub size: u32,
    /// The date and time stamp value.
    ///
    /// The value is represented in the number of seconds elapsed since midnight
    /// (00:00:00), January 1, 1970, Universal Coordinated Time, according to the
    /// system clock.
    pub time_stamp: u32,
    /// The major version number.
    pub major_version: u16,
    /// The minor version number.
    pub minor_version: u16,
    /// Global flags to clear.
    pub global_flags_clear: u32,
    /// Global flags to set.
    pub global_flags_set: u32,
    /// Default timeout value for critical sections.
    pub critical_section_default_timeout: u32,
    /// Threshold for decommitting free blocks.
    pub de_commit_free_block_threshold: u64,
    /// Total threshold for decommitting memory.
    pub de_commit_total_free_threshold: u64,
    /// Virtual address of the lock prefix table.
    pub lock_prefix_table: u64,
    /// Maximum allocation size allowed.
    pub maximum_allocation_size: u64,
    /// Threshold for allocating virtual memory.
    pub virtual_memory_threshold: u64,
    /// Process affinity mask.
    pub process_affinity_mask: u64,
    /// Heap flags for the process.
    pub process_heap_flags: u32,
    /// Service pack version (CSD Version).
    pub csd_version: u16,
    /// Dependent load flags.
    pub dependent_load_flags: u16,
    /// Virtual address of the edit list.
    pub edit_list: u64,
    /// Virtual address of the security cookie.
    pub security_cookie: u64,
    /// Virtual address of the SE handler table.
    pub se_handler_table: u64,
    /// Count of SE handlers.
    pub se_handler_count: u64,
    /// Virtual address of the Guard CF check function pointer.
    pub guard_cf_check_function_pointer: u64,
    /// Virtual address of the Guard CF dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u64,
    /// Virtual address of the Guard CF function table.
    pub guard_cf_function_table: u64,
    /// Count of Guard CF functions.
    pub guard_cf_function_count: u64,
    /// Flags related to Control Flow Guard (CFG).
    pub guard_flags: u32,
    /// Code integrity configuration.
    pub code_integrity: LoadConfigCodeIntegrity,
    /// Virtual address of the Guard address-taken IAT entry table.
    pub guard_address_taken_iat_entry_table: u64,
    /// Count of Guard address-taken IAT entries.
    pub guard_address_taken_iat_entry_count: u64,
    /// Virtual address of the Guard long jump target table.
    pub guard_long_jump_target_table: u64,
    /// Count of Guard long jump targets.
    pub guard_long_jump_target_count: u64,
    /// Virtual address of the dynamic value relocation table.
    pub dynamic_value_reloc_table: u64,
    /// Virtual address of the CHPE metadata.
    pub chpe_metadata_pointer: u64,
    /// Virtual address of the Guard RF failure routine.
    pub guard_rf_failure_routine: u64,
    /// Virtual address of the Guard RF failure routine function pointer.
    pub guard_rf_failure_routine_function_pointer: u64,
    /// Offset of the dynamic value relocation table.
    pub dynamic_value_reloc_table_offset: u32,
    /// Section index of the dynamic value relocation table.
    pub dynamic_value_reloc_table_section: u16,
    /// Reserved field.
    pub reserved2: u16,
    /// Virtual address of the Guard RF verify stack pointer function pointer.
    pub guard_rf_verify_stack_pointer_function_pointer: u64,
    /// Offset to the hot patch table.
    pub hot_patch_table_offset: u32,
    /// Reserved field.
    pub reserved3: u32,
    /// Virtual address of the enclave configuration pointer.
    pub enclave_configuration_pointer: u64,
    /// Virtual address of the volatile metadata pointer.
    pub volatile_metadata_pointer: u64,
    /// Virtual address of the Guard EH continuation table.
    pub guard_eh_continuation_table: u64,
    /// Count of Guard EH continuations.
    pub guard_eh_continuation_count: u64,
    /// Virtual address of the Guard XFG check function pointer.
    pub guard_xfg_check_function_pointer: u64,
    /// Virtual address of the Guard XFG dispatch function pointer.
    pub guard_xfg_dispatch_function_pointer: u64,
    /// Virtual address of the Guard XFG table dispatch function pointer.
    pub guard_xfg_table_dispatch_function_pointer: u64,
    /// Virtual address of the CASTGuard OS-determined failure mode handler.
    pub cast_guard_os_determined_failure_mode: u64,
    /// Virtual address of the Guard memcpy function pointer.
    pub guard_memcpy_function_pointer: u64,
}

/// Represents the 32-bit Load Configuration directory structure of a PE file.
///
/// This structure contains information related to the loading configuration
/// of a PE (Portable Executable) file. It provides details for various
/// configuration settings that the operating system loader may use when loading
/// the PE file into memory. This structure is marked as non_exhaustive, meaning
/// that future versions of the PE format may include additional fields that are
/// not present in the current version of this structure.
///
/// # Notes
///
/// This structure may grow in future versions of the PE format, so be cautious
/// when working with it, as some fields may not be available or relevant for
/// all versions of PE files.
#[repr(C)]
#[non_exhaustive]
#[derive(Debug, Clone, Pread, Pwrite, SizeWith, Eq, PartialEq)]
pub struct LoadConfigDirectory32 {
    /// The size of the structure.
    pub size: u32,
    /// The date and time stamp value.
    ///
    /// The value is represented in the number of seconds elapsed since midnight
    /// (00:00:00), January 1, 1970, Universal Coordinated Time, according to the
    /// system clock.
    pub time_stamp: u32,
    /// The major version number.
    pub major_version: u16,
    /// The minor version number.
    pub minor_version: u16,
    /// Global flags to clear.
    pub global_flags_clear: u32,
    /// Global flags to set.
    pub global_flags_set: u32,
    /// Default timeout value for critical sections.
    pub critical_section_default_timeout: u32,
    /// Threshold for decommitting free blocks.
    pub de_commit_free_block_threshold: u32,
    /// Total threshold for decommitting memory.
    pub de_commit_total_free_threshold: u32,
    /// Virtual address of the lock prefix table.
    pub lock_prefix_table: u32,
    /// Maximum allocation size allowed.
    pub maximum_allocation_size: u32,
    /// Threshold for allocating virtual memory.
    pub virtual_memory_threshold: u32,
    /// Heap flags for the process.
    pub process_heap_flags: u32,
    /// Process affinity mask.
    pub process_affinity_mask: u32,
    /// Service pack version (CSD Version).
    pub csd_version: u16,
    /// Dependent load flags.
    pub dependent_load_flags: u16,
    /// Virtual address of the edit list.
    pub edit_list: u32,
    /// Virtual address of the security cookie.
    pub security_cookie: u32,
    /// Virtual address of the SE handler table.
    pub se_handler_table: u32,
    /// Count of SE handlers.
    pub se_handler_count: u32,
    /// Virtual address of the Guard CF check function pointer.
    pub guard_cf_check_function_pointer: u32,
    /// Virtual address of the Guard CF dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u32,
    /// Virtual address of the Guard CF function table.
    pub guard_cf_function_table: u32,
    /// Count of Guard CF functions.
    pub guard_cf_function_count: u32,
    /// Flags related to Control Flow Guard (CFG).
    pub guard_flags: u32,
    /// Code integrity configuration.
    pub code_integrity: LoadConfigCodeIntegrity,
    /// Virtual address of the Guard address-taken IAT entry table.
    pub guard_address_taken_iat_entry_table: u32,
    /// Count of Guard address-taken IAT entries.
    pub guard_address_taken_iat_entry_count: u32,
    /// Virtual address of the Guard long jump target table.
    pub guard_long_jump_target_table: u32,
    /// Count of Guard long jump targets.
    pub guard_long_jump_target_count: u32,
    /// Virtual address of the dynamic value relocation table.
    pub dynamic_value_reloc_table: u32,
    /// Virtual address of the CHPE metadata.
    pub chpe_metadata_pointer: u32,
    /// Virtual address of the Guard RF failure routine.
    pub guard_rf_failure_routine: u32,
    /// Virtual address of the Guard RF failure routine function pointer.
    pub guard_rf_failure_routine_function_pointer: u32,
    /// Offset of the dynamic value relocation table.
    pub dynamic_value_reloc_table_offset: u32,
    /// Section index of the dynamic value relocation table.
    pub dynamic_value_reloc_table_section: u16,
    /// Reserved field.
    pub reserved2: u16,
    /// Virtual address of the Guard RF verify stack pointer function pointer.
    pub guard_rf_verify_stack_pointer_function_pointer: u32,
    /// Offset to the hot patch table.
    pub hot_patch_table_offset: u32,
    /// Reserved field.
    pub reserved3: u32,
    /// Virtual address of the enclave configuration pointer.
    pub enclave_configuration_pointer: u32,
    /// Virtual address of the volatile metadata pointer.
    pub volatile_metadata_pointer: u32,
    /// Virtual address of the Guard EH continuation table.
    pub guard_eh_continuation_table: u32,
    /// Count of Guard EH continuations.
    pub guard_eh_continuation_count: u32,
    /// Virtual address of the Guard XFG check function pointer.
    pub guard_xfg_check_function_pointer: u32,
    /// Virtual address of the Guard XFG dispatch function pointer.
    pub guard_xfg_dispatch_function_pointer: u32,
    /// Virtual address of the Guard XFG table dispatch function pointer.
    pub guard_xfg_table_dispatch_function_pointer: u32,
    /// Virtual address of the CASTGuard OS-determined failure mode handler.
    pub cast_guard_os_determined_failure_mode: u32,
    /// Virtual address of the Guard memcpy function pointer.
    pub guard_memcpy_function_pointer: u32,
}

/// Macro that checks if the given structure has a field available
/// based on a size check.
macro_rules! have_field {
    ($bytes:expr, $size:expr, $offset:expr, $ty:ty) => {
        ($size as usize >= $offset + ::core::mem::size_of::<$ty>())
            .then(|| $bytes.pread::<$ty>($offset).ok())
            .flatten()
    };
}

/// Represents the code integrity configuration used in load configuration.
#[repr(C)]
#[derive(Debug, Clone, Pread, Pwrite, SizeWith, Eq, PartialEq)]
pub struct LoadConfigCodeIntegrity {
    /// Flags indicating code integrity options.
    pub flags: u16,
    /// Catalog index.
    pub catalog: u16,
    /// Offset to the catalog.
    pub catalog_offset: u32,
    /// Reserved field.
    pub reserved: u32,
}

/// Represents a PE load config directory data.
///
/// This struct encapsulates the raw bytes of a [`LoadConfigDirectory`], and provides
/// access to its fields through accessor methods.
///
/// # Important
///
/// The layout and size of the [LoadConfigDirectory] may vary between Windows versions
/// and toolchains. To keep it future-proof, you **must not** access the
/// underlying bytes directly or assume a fixed structure.
///
/// Always use the provided accessor methods to retrieve field values. This ensures
/// compatibility with potential changes in the Load Config Directory layout and
/// helps avoid subtle bugs when parsing binaries built with different configurations.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct LoadConfigData<'a> {
    /// Whether the binary is 64-bit.
    is_64: bool,
    /// Raw bytes covering the entire bytes of the load config directory.
    bytes: &'a [u8],
    /// The struct size [LoadConfigDirectory::size] read from first
    /// 4 bytes of [LoadConfigData::bytes].
    size: usize,
}

impl<'a> LoadConfigData<'a> {
    pub fn parse(
        bytes: &'a [u8],
        dd: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        is_64: bool,
    ) -> error::Result<Self> {
        Self::parse_with_opts(
            bytes,
            dd,
            sections,
            file_alignment,
            &options::ParseOptions::default(),
            is_64,
        )
    }

    pub fn parse_with_opts(
        bytes: &'a [u8],
        dd: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        opts: &options::ParseOptions,
        is_64: bool,
    ) -> error::Result<Self> {
        let offset =
            utils::find_offset(dd.virtual_address as usize, sections, file_alignment, opts)
                .ok_or_else(|| {
                    error::Error::Malformed(format!(
                        "Cannot map load config rva {:#x} into offset",
                        dd.virtual_address
                    ))
                })?;
        let bytes = bytes[offset..]
            .pread::<&[u8]>(dd.size as usize)
            .map_err(|_| {
                error::Error::Malformed(format!(
                    "load config offset {:#x} and size {:#x} exceeds the bounds of the bytes size {:#x}",
                    offset,
                    dd.size,
                    bytes.len()
                ))
            })?;
        let size = bytes.pread::<u32>(0).map_err(|_| {
            error::Error::Malformed(format!("cannot read cb size ({})", bytes.len()))
        })? as usize;

        Ok(Self { is_64, bytes, size })
    }

    /// Internal helper to read architecture-dependent values
    fn read_arch_dependent_u64(&self, offset: usize) -> Option<u64> {
        if self.is_64 {
            have_field!(self.bytes, self.size, offset, u64)
        } else {
            have_field!(self.bytes, self.size, offset, u32).map(|v| v as u64)
        }
    }

    /// Returns the value of [LoadConfigDirectory::size].
    pub fn size(&self) -> u32 {
        self.size as u32
    }

    /// Returns the value of [LoadConfigDirectory::time_stamp].
    pub fn time_stamp(&self) -> Option<u32> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, time_stamp),
                u32
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, time_stamp),
                u32
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::major_version].
    pub fn major_version(&self) -> Option<u16> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, major_version),
                u16
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, major_version),
                u16
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::minor_version].
    pub fn minor_version(&self) -> Option<u16> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, minor_version),
                u16
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, minor_version),
                u16
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::global_flags_clear].
    pub fn global_flags_clear(&self) -> Option<u32> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, global_flags_clear),
                u32
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, global_flags_clear),
                u32
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::global_flags_set].
    pub fn global_flags_set(&self) -> Option<u32> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, global_flags_set),
                u32
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, global_flags_set),
                u32
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::critical_section_default_timeout].
    pub fn critical_section_default_timeout(&self) -> Option<u32> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, critical_section_default_timeout),
                u32
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, critical_section_default_timeout),
                u32
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::de_commit_free_block_threshold].
    pub fn de_commit_free_block_threshold(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                de_commit_free_block_threshold
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                de_commit_free_block_threshold
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::de_commit_total_free_threshold].
    pub fn de_commit_total_free_threshold(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                de_commit_total_free_threshold
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                de_commit_total_free_threshold
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::lock_prefix_table].
    pub fn lock_prefix_table(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, lock_prefix_table))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, lock_prefix_table))
        }
    }

    /// Returns the value of [LoadConfigDirectory::maximum_allocation_size].
    pub fn maximum_allocation_size(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, maximum_allocation_size))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, maximum_allocation_size))
        }
    }

    /// Returns the value of [LoadConfigDirectory::virtual_memory_threshold].
    pub fn virtual_memory_threshold(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                virtual_memory_threshold
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                virtual_memory_threshold
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::process_affinity_mask].
    pub fn process_affinity_mask(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, process_affinity_mask))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, process_affinity_mask))
        }
    }

    /// Returns the value of [LoadConfigDirectory::process_heap_flags].
    pub fn process_heap_flags(&self) -> Option<u32> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, process_heap_flags),
                u32
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, process_heap_flags),
                u32
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::csd_version].
    pub fn csd_version(&self) -> Option<u16> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, csd_version),
                u16
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, csd_version),
                u16
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::dependent_load_flags].
    pub fn dependent_load_flags(&self) -> Option<u16> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, dependent_load_flags),
                u16
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, dependent_load_flags),
                u16
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::edit_list].
    pub fn edit_list(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, edit_list))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, edit_list))
        }
    }

    /// Returns the value of [LoadConfigDirectory::security_cookie].
    pub fn security_cookie(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, security_cookie))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, security_cookie))
        }
    }

    /// Returns the value of [LoadConfigDirectory::se_handler_table].
    pub fn se_handler_table(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, se_handler_table))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, se_handler_table))
        }
    }

    /// Returns the value of [LoadConfigDirectory::se_handler_count].
    pub fn se_handler_count(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, se_handler_count))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, se_handler_count))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_cf_check_function_pointer].
    pub fn guard_cf_check_function_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_cf_check_function_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_cf_check_function_pointer
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_cf_dispatch_function_pointer].
    pub fn guard_cf_dispatch_function_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_cf_dispatch_function_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_cf_dispatch_function_pointer
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_cf_function_table].
    pub fn guard_cf_function_table(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, guard_cf_function_table))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, guard_cf_function_table))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_cf_function_count].
    pub fn guard_cf_function_count(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, guard_cf_function_count))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, guard_cf_function_count))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_flags].
    pub fn guard_flags(&self) -> Option<u32> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, guard_flags),
                u32
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, guard_flags),
                u32
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::code_integrity].
    pub fn code_integrity(&self) -> Option<LoadConfigCodeIntegrity> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, code_integrity),
                LoadConfigCodeIntegrity
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, code_integrity),
                LoadConfigCodeIntegrity
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_address_taken_iat_entry_table].
    pub fn guard_address_taken_iat_entry_table(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_address_taken_iat_entry_table
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_address_taken_iat_entry_table
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_address_taken_iat_entry_count].
    pub fn guard_address_taken_iat_entry_count(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_address_taken_iat_entry_count
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_address_taken_iat_entry_count
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_long_jump_target_table].
    pub fn guard_long_jump_target_table(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_long_jump_target_table
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_long_jump_target_table
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_long_jump_target_count].
    pub fn guard_long_jump_target_count(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_long_jump_target_count
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_long_jump_target_count
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::dynamic_value_reloc_table].
    pub fn dynamic_value_reloc_table(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                dynamic_value_reloc_table
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                dynamic_value_reloc_table
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::chpe_metadata_pointer].
    pub fn chpe_metadata_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory64, chpe_metadata_pointer))
        } else {
            self.read_arch_dependent_u64(offset_of!(LoadConfigDirectory32, chpe_metadata_pointer))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_rf_failure_routine].
    pub fn guard_rf_failure_routine(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_rf_failure_routine
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_rf_failure_routine
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_rf_failure_routine_function_pointer].
    pub fn guard_rf_failure_routine_function_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_rf_failure_routine_function_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_rf_failure_routine_function_pointer
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::dynamic_value_reloc_table_offset].
    pub fn dynamic_value_reloc_table_offset(&self) -> Option<u32> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, dynamic_value_reloc_table_offset),
                u32
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, dynamic_value_reloc_table_offset),
                u32
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::dynamic_value_reloc_table_section].
    pub fn dynamic_value_reloc_table_section(&self) -> Option<u16> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, dynamic_value_reloc_table_section),
                u16
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, dynamic_value_reloc_table_section),
                u16
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::reserved2].
    pub fn reserved2(&self) -> Option<u16> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, reserved2),
                u16
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, reserved2),
                u16
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_rf_verify_stack_pointer_function_pointer].
    pub fn guard_rf_verify_stack_pointer_function_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_rf_verify_stack_pointer_function_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_rf_verify_stack_pointer_function_pointer
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::hot_patch_table_offset].
    pub fn hot_patch_table_offset(&self) -> Option<u32> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, hot_patch_table_offset),
                u32
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, hot_patch_table_offset),
                u32
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::reserved3].
    pub fn reserved3(&self) -> Option<u32> {
        if self.is_64 {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory64, reserved3),
                u32
            )
        } else {
            have_field!(
                self.bytes,
                self.size,
                offset_of!(LoadConfigDirectory32, reserved3),
                u32
            )
        }
    }

    /// Returns the value of [LoadConfigDirectory::enclave_configuration_pointer].
    pub fn enclave_configuration_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                enclave_configuration_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                enclave_configuration_pointer
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::volatile_metadata_pointer].
    pub fn volatile_metadata_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                volatile_metadata_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                volatile_metadata_pointer
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_eh_continuation_table].
    pub fn guard_eh_continuation_table(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_eh_continuation_table
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_eh_continuation_table
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_eh_continuation_count].
    pub fn guard_eh_continuation_count(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_eh_continuation_count
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_eh_continuation_count
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_xfg_check_function_pointer].
    pub fn guard_xfg_check_function_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_xfg_check_function_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_xfg_check_function_pointer
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_xfg_dispatch_function_pointer].
    pub fn guard_xfg_dispatch_function_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_xfg_dispatch_function_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_xfg_dispatch_function_pointer
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_xfg_table_dispatch_function_pointer].
    pub fn guard_xfg_table_dispatch_function_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_xfg_table_dispatch_function_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_xfg_table_dispatch_function_pointer
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::cast_guard_os_determined_failure_mode].
    pub fn cast_guard_os_determined_failure_mode(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                cast_guard_os_determined_failure_mode
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                cast_guard_os_determined_failure_mode
            ))
        }
    }

    /// Returns the value of [LoadConfigDirectory::guard_memcpy_function_pointer].
    pub fn guard_memcpy_function_pointer(&self) -> Option<u64> {
        if self.is_64 {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory64,
                guard_memcpy_function_pointer
            ))
        } else {
            self.read_arch_dependent_u64(offset_of!(
                LoadConfigDirectory32,
                guard_memcpy_function_pointer
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOADCONFIG64_DATA0: &[u8; 320] = &[
        0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x45,
        0x1E, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x12, 0x1E, 0x80, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x50, 0x1E, 0x80, 0x01, 0x00, 0x00, 0x00, 0xA0, 0x02, 0x17, 0x80, 0x01, 0x00, 0x00,
        0x00, 0x87, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x75, 0x41, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0,
        0x06, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0xFF, 0x16, 0x80, 0x01, 0x00,
        0x00, 0x00, 0xAE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x50, 0x1E, 0x80, 0x01,
        0x00, 0x00, 0x00, 0x10, 0x50, 0x1E, 0x80, 0x01, 0x00, 0x00, 0x00, 0x18, 0x50, 0x1E, 0x80,
        0x01, 0x00, 0x00, 0x00, 0x20, 0x50, 0x1E, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const LOADCONFIG32_DATA0: &[u8; 192] = &[
        0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0xD0, 0x41, 0x00, 0xD4, 0xB6, 0x41, 0x00, 0x10, 0x00, 0x00, 0x00, 0x70, 0x51, 0x41,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xBC, 0x51, 0x41, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x75,
        0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xD4, 0xDC, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_load_config_sizes() {
        assert_eq!(core::mem::size_of::<LoadConfigDirectory32>(), 192);
        assert_eq!(core::mem::size_of::<LoadConfigDirectory64>(), 320);
    }

    #[test]
    fn parse_loadconfig64_data0() {
        let size = LOADCONFIG64_DATA0.pread::<u32>(0).unwrap();
        let data = LoadConfigData {
            is_64: true,
            bytes: LOADCONFIG64_DATA0,
            size: size as usize,
        };

        assert_eq!(data.size(), 320);
        assert_eq!(data.time_stamp(), Some(0));
        assert_eq!(data.major_version(), Some(0));
        assert_eq!(data.minor_version(), Some(0));
        assert_eq!(data.global_flags_clear(), Some(0));
        assert_eq!(data.global_flags_set(), Some(0));
        assert_eq!(data.critical_section_default_timeout(), Some(0));
        assert_eq!(data.de_commit_free_block_threshold(), Some(0));
        assert_eq!(data.de_commit_total_free_threshold(), Some(0));
        assert_eq!(data.lock_prefix_table(), Some(0));
        assert_eq!(data.maximum_allocation_size(), Some(0));
        assert_eq!(data.virtual_memory_threshold(), Some(0));
        assert_eq!(data.process_affinity_mask(), Some(0));
        assert_eq!(data.process_heap_flags(), Some(0));
        assert_eq!(data.csd_version(), Some(0));
        assert_eq!(
            data.dependent_load_flags(),
            Some(LOAD_LIBRARY_SEARCH_SYSTEM32 as u16)
        );
        assert_eq!(data.edit_list(), Some(0));
        assert_eq!(data.security_cookie(), Some(0x1801e4598));
        assert_eq!(data.se_handler_table(), Some(0));
        assert_eq!(data.se_handler_count(), Some(0));
        assert_eq!(data.guard_cf_check_function_pointer(), Some(0x1801e1218));
        assert_eq!(data.guard_cf_dispatch_function_pointer(), Some(0x1801e5000));
        assert_eq!(data.guard_cf_function_table(), Some(0x1801702a0));
        assert_eq!(data.guard_cf_function_count(), Some(2183));
        // Instrumented, Function table, Delay-load IAT protected, Delay-load private section,
        // Export information suppression, Longjump table, EH continuation table
        assert_eq!(data.guard_flags(), Some(0x10417500));
        const FLAGS: u32 = IMAGE_GUARD_CF_INSTRUMENTED
            | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
            | IMAGE_GUARD_PROTECT_DELAYLOAD_IAT
            | IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION
            | IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT
            | IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT
            | IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT;
        assert_eq!(data.guard_flags().map(|x| x & FLAGS), Some(FLAGS));
        assert_eq!(
            data.code_integrity(),
            Some(LoadConfigCodeIntegrity {
                flags: 0,
                catalog: 0,
                catalog_offset: 0,
                reserved: 0
            })
        );
        assert_eq!(data.guard_address_taken_iat_entry_table(), Some(0));
        assert_eq!(data.guard_address_taken_iat_entry_count(), Some(0));
        assert_eq!(data.guard_long_jump_target_table(), Some(0));
        assert_eq!(data.guard_long_jump_target_count(), Some(0));
        assert_eq!(data.dynamic_value_reloc_table(), Some(0));
        assert_eq!(data.chpe_metadata_pointer(), Some(0));
        assert_eq!(data.guard_rf_failure_routine(), Some(0));
        assert_eq!(data.guard_rf_failure_routine_function_pointer(), Some(0));
        assert_eq!(data.dynamic_value_reloc_table_offset(), Some(0x6a0));
        assert_eq!(data.dynamic_value_reloc_table_section(), Some(15));
        assert_eq!(data.reserved2(), Some(0));
        assert_eq!(
            data.guard_rf_verify_stack_pointer_function_pointer(),
            Some(0)
        );
        assert_eq!(data.hot_patch_table_offset(), Some(0));
        assert_eq!(data.reserved3(), Some(0));
        assert_eq!(data.enclave_configuration_pointer(), Some(0));
        assert_eq!(data.volatile_metadata_pointer(), Some(0));
        assert_eq!(data.guard_eh_continuation_table(), Some(0x18016ff38));
        assert_eq!(data.guard_eh_continuation_count(), Some(174));
        assert_eq!(data.guard_xfg_check_function_pointer(), Some(0x1801e5008));
        assert_eq!(
            data.guard_xfg_dispatch_function_pointer(),
            Some(0x1801e5010)
        );
        assert_eq!(
            data.guard_xfg_table_dispatch_function_pointer(),
            Some(0x1801e5018)
        );
        assert_eq!(
            data.cast_guard_os_determined_failure_mode(),
            Some(0x1801e5020)
        );
        assert_eq!(data.guard_memcpy_function_pointer(), Some(0));
    }

    #[test]
    fn parse_loadconfig32_data0() {
        let size = LOADCONFIG32_DATA0.pread::<u32>(0).unwrap();
        let data = LoadConfigData {
            is_64: false,
            bytes: LOADCONFIG32_DATA0,
            size: size as usize,
        };

        assert_eq!(data.size(), 188);
        assert_eq!(data.time_stamp(), Some(0));
        assert_eq!(data.major_version(), Some(0));
        assert_eq!(data.minor_version(), Some(0));
        assert_eq!(data.global_flags_clear(), Some(0));
        assert_eq!(data.global_flags_set(), Some(0));
        assert_eq!(data.critical_section_default_timeout(), Some(0));
        assert_eq!(data.de_commit_free_block_threshold(), Some(0));
        assert_eq!(data.de_commit_total_free_threshold(), Some(0));
        assert_eq!(data.lock_prefix_table(), Some(0));
        assert_eq!(data.maximum_allocation_size(), Some(0));
        assert_eq!(data.virtual_memory_threshold(), Some(0));
        assert_eq!(data.process_affinity_mask(), Some(0));
        assert_eq!(data.process_heap_flags(), Some(0));
        assert_eq!(data.csd_version(), Some(0));
        assert_eq!(data.dependent_load_flags(), Some(0));
        assert_eq!(data.edit_list(), Some(0));
        assert_eq!(data.security_cookie(), Some(0x41d008));
        assert_eq!(data.se_handler_table(), Some(0x41b6d4));
        assert_eq!(data.se_handler_count(), Some(16));
        assert_eq!(data.guard_cf_check_function_pointer(), Some(0x415170));
        assert_eq!(data.guard_cf_dispatch_function_pointer(), Some(0));
        assert_eq!(data.guard_cf_function_table(), Some(0x4151bc));
        assert_eq!(data.guard_cf_function_count(), Some(63));
        // Instrumented, Function table, Delay-load IAT protected, Delay-load private section,
        // Export information suppression, Longjump table
        assert_eq!(data.guard_flags(), Some(0x10017500));
        const FLAGS: u32 = IMAGE_GUARD_CF_INSTRUMENTED
            | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
            | IMAGE_GUARD_PROTECT_DELAYLOAD_IAT
            | IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION
            | IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT
            | IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT;
        assert_eq!(data.guard_flags().map(|x| x & FLAGS), Some(FLAGS));
        assert_eq!(
            data.code_integrity(),
            Some(LoadConfigCodeIntegrity {
                flags: 0,
                catalog: 0,
                catalog_offset: 0,
                reserved: 0
            })
        );
        assert_eq!(data.guard_address_taken_iat_entry_table(), Some(0));
        assert_eq!(data.guard_address_taken_iat_entry_count(), Some(0));
        assert_eq!(data.guard_long_jump_target_table(), Some(0));
        assert_eq!(data.guard_long_jump_target_count(), Some(0));
        assert_eq!(data.dynamic_value_reloc_table(), Some(0));
        assert_eq!(data.chpe_metadata_pointer(), Some(0));
        assert_eq!(data.guard_rf_failure_routine(), Some(0));
        assert_eq!(data.guard_rf_failure_routine_function_pointer(), Some(0));
        assert_eq!(data.dynamic_value_reloc_table_offset(), Some(0));
        assert_eq!(data.dynamic_value_reloc_table_section(), Some(0));
        assert_eq!(data.reserved2(), Some(0));
        assert_eq!(
            data.guard_rf_verify_stack_pointer_function_pointer(),
            Some(0)
        );
        assert_eq!(data.hot_patch_table_offset(), Some(0));
        assert_eq!(data.reserved3(), Some(0));
        assert_eq!(data.enclave_configuration_pointer(), Some(0));
        assert_eq!(data.volatile_metadata_pointer(), Some(0));
        assert_eq!(data.guard_eh_continuation_table(), Some(0));
        assert_eq!(data.guard_eh_continuation_count(), Some(0));
        assert_eq!(data.guard_xfg_check_function_pointer(), Some(0));
        assert_eq!(data.guard_xfg_dispatch_function_pointer(), Some(0));
        assert_eq!(data.guard_xfg_table_dispatch_function_pointer(), Some(0));
        assert_eq!(data.cast_guard_os_determined_failure_mode(), Some(0x41dcd4));
        assert_eq!(data.guard_memcpy_function_pointer(), None);
    }
}
