use scroll::ctx;
use scroll::{Pread, Pwrite, SizeWith};

use crate::container::{Container, Ctx};
use crate::error;
use crate::options::Permissive;
use crate::pe::ctx::PeCtx;
use crate::pe::data_directories;
use crate::pe::import::{IMPORT_BY_ORDINAL_32, IMPORT_BY_ORDINAL_64};
use crate::pe::options;
use crate::pe::section_table;
use crate::pe::utils;

#[derive(Debug, Default)]
pub struct DelayImportFunction<'a> {
    pub name: Option<&'a str>,
    pub ordinal: u16,
}

impl<'a> ctx::TryFromCtx<'a, (DelayImportDescriptor, PeCtx<'a>)> for DelayImportFunction<'a> {
    type Error = crate::error::Error;
    fn try_from_ctx(
        bytes: &'a [u8],
        (descriptor, ctx): (DelayImportDescriptor, PeCtx<'a>),
    ) -> error::Result<(Self, usize)> {
        let mut offset = 0;

        let thunk =
            bytes.gread_with::<DelayImportThunk>(&mut offset, Ctx::new(ctx.container, ctx.le))?;
        if thunk.is_null() {
            return Ok((DelayImportFunction::default(), offset));
        }

        let is_ordinal = if ctx.is_big() {
            thunk.is_ordinal64()
        } else {
            thunk.is_ordinal32()
        };

        let (name, ordinal) = if is_ordinal {
            (None, thunk.ordinal())
        } else {
            let dll_name_rva = descriptor.name_rva;
            let dll_name_offset = utils::find_offset(
                dll_name_rva as usize,
                ctx.sections,
                ctx.file_alignment,
                &ctx.opts,
            )
            .ok_or_else(|| {
                error::Error::Malformed(format!(
                    "cannot map delay import dll name rva {dll_name_rva:#x}"
                ))
            })
            .or_permissive_and_then(
                ctx.opts.parse_mode.is_permissive(),
                &format!(
                    "cannot map delay import dll name rva {dll_name_rva:#x}; treating as empty"
                ),
                || 0,
            )?;
            if dll_name_offset == 0 {
                (None, 0) // 0 = not ordinal (ordinal starts from 1)
            } else {
                let dll_name = ctx.bytes.pread::<&'a str>(dll_name_offset)?;
                (Some(dll_name), 0) // 0 = not ordinal (ordinal starts from 1)
            }
        };

        let func = DelayImportFunction { name, ordinal };

        Ok((func, offset))
    }
}

#[derive(Debug)]
pub struct DelayImportDll<'a> {
    pub descriptor: DelayImportDescriptor,
    ctx: PeCtx<'a>,
    bytes: &'a [u8],
}

impl<'a> DelayImportDll<'a> {
    pub fn functions(
        &self,
        sections: &'a [section_table::SectionTable],
    ) -> DelayImportFunctionIterator<'a> {
        // Replace sections with an actual sections ref
        let pectx = PeCtx {
            sections,
            ..self.ctx
        };
        DelayImportFunctionIterator {
            ctx: pectx,
            bytes: self.bytes,
            offset: 0,
            descriptor: self.descriptor,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DelayImportDllIterator<'a> {
    ctx: PeCtx<'a>,
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for DelayImportDllIterator<'a> {
    type Item = DelayImportDll<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let descriptor = self
            .bytes
            .gread_with::<DelayImportDescriptor>(&mut self.offset, scroll::LE)
            .ok()?;
        if descriptor.is_null() || !descriptor.is_possibly_valid() {
            self.bytes = &[];
            return None;
        }

        let name_table_rva = descriptor.name_table_rva;
        let name_table_offset = utils::find_offset(
            name_table_rva as usize,
            self.ctx.sections,
            self.ctx.file_alignment,
            &self.ctx.opts,
        )?;
        if self.ctx.bytes.len() < name_table_offset {
            self.bytes = &[];
            return None;
        }

        let res = DelayImportDll {
            descriptor,
            ctx: self.ctx,
            bytes: &self.ctx.bytes[name_table_offset..],
        };

        Some(res)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DelayImportFunctionIterator<'a> {
    ctx: PeCtx<'a>,
    bytes: &'a [u8],
    offset: usize,
    descriptor: DelayImportDescriptor,
}

impl<'a> Iterator for DelayImportFunctionIterator<'a> {
    type Item = DelayImportFunction<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let ctx = Ctx::new(self.ctx.container, scroll::LE);
        let thunk = self
            .bytes
            .gread_with::<DelayImportThunk>(&mut self.offset, ctx)
            .ok()?;
        if thunk.is_null() {
            self.bytes = &[];
            return None;
        }

        let ctx = (self.descriptor, self.ctx);
        let func = self.bytes.pread_with::<DelayImportFunction>(0, ctx).ok()?;

        Some(func)
    }
}

/// Represents a single entry in the delay import table of a PE (Portable Executable) file.
#[derive(Debug)]
pub struct DelayImportEntry<'a> {
    /// The associated delay import descriptor.
    pub descriptor: DelayImportDescriptor,
    /// Name offset of this delay import entry.
    pub offset: u32,
    /// RVA of this delay import entry.
    pub rva: u32,
    /// Hint value for symbol lookup.
    pub hint: u16,
    /// Name of the DLL this function is imported from.
    pub dll: &'a str,
    /// Name of the imported function, if available.
    ///
    /// This is `None` if the import is by ordinal.
    pub name: Option<&'a str>,
    /// Ordinal number if the function is imported by ordinal.
    ///
    /// This is `0` if `name` is `Some` and vice versa.
    pub ordinal: u16,
}

/// Internal helper struct to simplify bitflag operations.
#[derive(Debug, SizeWith)]
pub struct DelayImportThunk(pub u64);

impl<'a> ctx::TryFromCtx<'a, Ctx> for DelayImportThunk {
    type Error = crate::error::Error;
    fn try_from_ctx(bytes: &'a [u8], ctx: Ctx) -> error::Result<(Self, usize)> {
        let mut offset = 0;

        let value = if ctx.is_big() {
            bytes.gread_with::<u64>(&mut offset, scroll::LE)?
        } else {
            let v = bytes.gread_with::<u32>(&mut offset, scroll::LE)?;
            v as u64
        };

        Ok((Self(value), offset))
    }
}

impl DelayImportThunk {
    /// Whether the entry is imported by ordinal (64-bit)
    pub fn is_ordinal64(&self) -> bool {
        self.0 & IMPORT_BY_ORDINAL_64 != 0
    }

    /// Whether the entry is imported by ordinal (32-bit)
    pub fn is_ordinal32(&self) -> bool {
        (self.0 as u32) & IMPORT_BY_ORDINAL_32 != 0
    }

    /// Returns the ordinal value
    ///
    /// Use this function if either `is_ordinal64` or `is_ordinal32` returns `true`.
    pub fn ordinal(&self) -> u16 {
        (self.0 as u16) & 0xFFFFu16
    }

    /// Returns the name rva value
    ///
    /// Use this function if either `is_ordinal64` or `is_ordinal32` returns `false`.
    pub fn name_rva(&self) -> u32 {
        self.0 as u32
    }

    /// Checks if the underlying value is zero.
    pub fn is_null(&self) -> bool {
        self.0 == 0
    }
}

/// Represents a delay-load import descriptor in a PE (Portable Executable) file.
///
/// This structure corresponds to the `IMAGE_DELAYLOAD_DESCRIPTOR` defined in the PE/COFF specification.
/// Each instance describes a single delay-loaded DLL and its associated import data.
#[derive(Debug, Copy, Clone, Pread, Pwrite, SizeWith)]
#[repr(C)]
pub struct DelayImportDescriptor {
    /// Attributes describing the delay load characteristics (e.g. pointer size, flags).
    pub attributes: u32,
    /// RVA of a null-terminated string containing the DLL name.
    pub name_rva: u32,
    /// RVA to a handle location that will store the DLL module handle after loading.
    pub handle_rva: u32,
    /// RVA of the delay-load Import Address Table (IAT).
    pub address_table_rva: u32,
    /// RVA of the delay-load Import Name Table (INT).
    pub name_table_rva: u32,
    /// RVA of the bound import address table (optional; used if binding is supported).
    pub bound_table_rva: u32,
    /// RVA of the unload import address table (optional; used during DLL unloading).
    pub unload_table_rva: u32,
    /// Timestamp of the bound DLL; zero if not bound.
    pub time_stamp: u32,
}

impl<'a> DelayImportDescriptor {
    /// Returns whether the RVA is based (RvaBased field).
    pub fn rva_based(&self) -> bool {
        self.attributes & 0x1 != 0
    }

    /// Returns the ReservedAttributes field (31 bits).
    pub fn reserved_attributes(&self) -> u32 {
        self.attributes >> 1
    }

    /// Whether the entire fields are set to zero
    pub fn is_null(&self) -> bool {
        self.attributes == 0
            && self.name_rva == 0
            && self.handle_rva == 0
            && self.address_table_rva == 0
            && self.name_table_rva == 0
            && self.bound_table_rva == 0
            && self.unload_table_rva == 0
            && self.time_stamp == 0
    }

    /// Whether the entry is _possibly_ valid.
    ///
    /// Both [`Self::name_rva`] and [`Self::address_table_rva`] must be non-zero
    pub fn is_possibly_valid(&self) -> bool {
        self.name_rva != 0 && self.address_table_rva != 0
    }
}

/// Represents a PE delay import directory data.
#[derive(Debug)]
pub struct DelayImportData<'a> {
    ctx: PeCtx<'a>,
    bytes: &'a [u8],
}

impl<'a> DelayImportData<'a> {
    pub fn parse(
        bytes: &'a [u8],
        dd: data_directories::DataDirectory,
        sections: &[section_table::SectionTable],
        file_alignment: u32,
        is_64: bool,
    ) -> error::Result<DelayImportData<'a>> {
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
    ) -> error::Result<DelayImportData<'a>> {
        let offset =
            utils::find_offset(dd.virtual_address as usize, sections, file_alignment, opts)
                .ok_or_else(|| {
                    error::Error::Malformed(format!(
                        "cannot map delay import table {:#x}",
                        dd.virtual_address
                    ))
                })?;
        let directory_bytes = bytes
            .pread_with::<&[u8]>(offset, dd.size as usize)
            .map_err(|_| {
                error::Error::Malformed(format!(
                    "delay import offset {offset:#x} and size {:#x} out of bounds",
                    dd.size
                ))
            })?;

        let container = if is_64 {
            Container::Big
        } else {
            Container::Little
        };
        // Avoid borrowing of sections here, we store the rest and modify sections field on demand
        let pectx = PeCtx::new(container, scroll::LE, &[], file_alignment, *opts, bytes);

        Ok(Self {
            ctx: pectx,
            bytes: directory_bytes,
        })
    }

    pub fn dlls(&self, sections: &'a [section_table::SectionTable]) -> DelayImportDllIterator<'a> {
        // Replace sections with an actual sections ref
        let pectx = PeCtx::new(
            self.ctx.container,
            self.ctx.le,
            &sections,
            self.ctx.file_alignment,
            self.ctx.opts,
            self.ctx.bytes,
        );
        DelayImportDllIterator {
            ctx: pectx,
            bytes: self.bytes,
            offset: 0,
        }
    }
}
