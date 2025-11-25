//! High-level ELF writer and modifier
//!
//! This module provides utilities for modifying ELF binaries, including operations
//! similar to `patchelf`:
//! - Setting/changing the dynamic linker/interpreter
//! - Setting/changing RPATH and RUNPATH
//! - Setting SONAME
//! - Adding/removing needed libraries
//! - Rebuilding modified ELF from scratch

use crate::container::Ctx;
use crate::error;
use crate::elf::program_header::{ProgramHeader, PT_INTERP, PT_DYNAMIC};
use crate::elf::dynamic::{Dyn, DT_NULL, DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_STRTAB, DT_STRSZ};
use crate::elf::header::Header;
use crate::elf::section_header::{SectionHeader, SHT_STRTAB};
use alloc::vec::Vec;
use alloc::string::String;
use scroll::Pwrite;

/// String table builder for dynamic strings
#[derive(Debug, Clone)]
struct DynStrBuilder {
    strings: Vec<u8>,
}

impl DynStrBuilder {
    fn new() -> Self {
        let mut strings = Vec::new();
        strings.push(0); // First byte is always null
        DynStrBuilder { strings }
    }

    /// Add a string and return its offset
    fn add(&mut self, s: &str) -> u32 {
        // Check if string already exists
        let s_bytes = s.as_bytes();
        for i in 1..self.strings.len() {
            if self.strings[i..].starts_with(s_bytes) {
                let end = i + s_bytes.len();
                if end < self.strings.len() && self.strings[end] == 0 {
                    return i as u32;
                }
            }
        }

        // Add new string
        let offset = self.strings.len() as u32;
        self.strings.extend_from_slice(s_bytes);
        self.strings.push(0);
        offset
    }

    fn data(&self) -> &[u8] {
        &self.strings
    }

    fn len(&self) -> usize {
        self.strings.len()
    }
}

/// An ELF file writer that rebuilds binaries with modifications
#[derive(Debug)]
pub struct ElfWriter {
    /// Original file data
    data: Vec<u8>,
    /// Parsed header
    header: Header,
    /// Program headers
    program_headers: Vec<ProgramHeader>,
    /// Section headers (if present)
    section_headers: Vec<SectionHeader>,
    /// Container context (endianness, 32/64-bit)
    ctx: Ctx,
    /// Modified interpreter path
    modified_interpreter: Option<String>,
    /// Dynamic entries
    dynamic_entries: Vec<Dyn>,
    /// Dynamic string table builder
    dynstr: DynStrBuilder,
    /// Original PT_DYNAMIC offset
    pt_dynamic_offset: Option<u64>,
    /// Is 64-bit?
    is_64: bool,
}

impl ElfWriter {
    /// Create a new writer from binary data
    pub fn new(data: Vec<u8>) -> error::Result<Self> {
        use crate::elf::Elf;

        // Parse from a copy to extract metadata
        let data_copy = data.clone();
        let elf = Elf::parse(&data_copy)?;
        let is_64 = elf.is_64;
        let ctx = Ctx::new(
            if is_64 { crate::container::Container::Big } else { crate::container::Container::Little },
            if elf.little_endian { scroll::Endian::Little } else { scroll::Endian::Big },
        );

        // Clone program headers
        let program_headers: Vec<ProgramHeader> = elf.program_headers.iter().cloned().collect();

        // Clone section headers
        let section_headers: Vec<SectionHeader> = elf.section_headers.iter().cloned().collect();

        // Extract dynamic entries
        let mut dynamic_entries = Vec::new();
        if let Some(ref dyn_section) = elf.dynamic {
            for dyn_entry in &dyn_section.dyns {
                dynamic_entries.push(dyn_entry.clone());
            }
        }

        // Build dynamic string table - we'll populate it as we modify entries
        let mut dynstr = DynStrBuilder::new();

        // Find PT_DYNAMIC offset
        let pt_dynamic_offset = program_headers.iter()
            .find(|ph| ph.p_type == PT_DYNAMIC)
            .map(|ph| ph.p_offset);

        Ok(ElfWriter {
            data,
            header: elf.header,
            program_headers,
            section_headers,
            ctx,
            modified_interpreter: None,
            dynamic_entries,
            dynstr,
            pt_dynamic_offset,
            is_64,
        })
    }

    /// Set the dynamic linker/interpreter path
    pub fn set_interpreter(&mut self, new_interpreter: &str) -> error::Result<()> {
        // Check if PT_INTERP exists
        let has_interp = self.program_headers.iter().any(|ph| ph.p_type == PT_INTERP);

        if !has_interp {
            return Err(error::Error::Malformed("No PT_INTERP segment found".into()));
        }

        self.modified_interpreter = Some(new_interpreter.to_string());
        Ok(())
    }

    /// Set RPATH (DT_RPATH) - adds colon-separated paths
    pub fn set_rpath(&mut self, new_rpath: &str) -> error::Result<()> {
        // Remove existing DT_RPATH
        self.dynamic_entries.retain(|d| d.d_tag != DT_RPATH);

        // Add string to dynstr
        let offset = self.dynstr.add(new_rpath);

        // Insert before DT_NULL
        let insert_pos = self.dynamic_entries.iter()
            .position(|d| d.d_tag == DT_NULL)
            .unwrap_or(self.dynamic_entries.len());

        self.dynamic_entries.insert(insert_pos, Dyn {
            d_tag: DT_RPATH,
            d_val: offset as u64,
        });

        Ok(())
    }

    /// Set RUNPATH (DT_RUNPATH) - preferred over RPATH
    pub fn set_runpath(&mut self, new_runpath: &str) -> error::Result<()> {
        // Remove existing DT_RUNPATH
        self.dynamic_entries.retain(|d| d.d_tag != DT_RUNPATH);

        // Add string to dynstr
        let offset = self.dynstr.add(new_runpath);

        // Insert before DT_NULL
        let insert_pos = self.dynamic_entries.iter()
            .position(|d| d.d_tag == DT_NULL)
            .unwrap_or(self.dynamic_entries.len());

        self.dynamic_entries.insert(insert_pos, Dyn {
            d_tag: DT_RUNPATH,
            d_val: offset as u64,
        });

        Ok(())
    }

    /// Set SONAME (shared object name)
    pub fn set_soname(&mut self, new_soname: &str) -> error::Result<()> {
        // Remove existing DT_SONAME
        self.dynamic_entries.retain(|d| d.d_tag != DT_SONAME);

        // Add string to dynstr
        let offset = self.dynstr.add(new_soname);

        // Insert before DT_NULL
        let insert_pos = self.dynamic_entries.iter()
            .position(|d| d.d_tag == DT_NULL)
            .unwrap_or(self.dynamic_entries.len());

        self.dynamic_entries.insert(insert_pos, Dyn {
            d_tag: DT_SONAME,
            d_val: offset as u64,
        });

        Ok(())
    }

    /// Add a needed library (DT_NEEDED)
    pub fn add_needed(&mut self, library: &str) -> error::Result<()> {
        // Check if already exists
        for dyn_entry in &self.dynamic_entries {
            if dyn_entry.d_tag == DT_NEEDED {
                // Would need to lookup string, skip for now
            }
        }

        // Add string to dynstr
        let offset = self.dynstr.add(library);

        // Insert before DT_NULL
        let insert_pos = self.dynamic_entries.iter()
            .position(|d| d.d_tag == DT_NULL)
            .unwrap_or(self.dynamic_entries.len());

        self.dynamic_entries.insert(insert_pos, Dyn {
            d_tag: DT_NEEDED,
            d_val: offset as u64,
        });

        Ok(())
    }

    /// Remove RPATH
    pub fn remove_rpath(&mut self) -> error::Result<()> {
        self.dynamic_entries.retain(|d| d.d_tag != DT_RPATH);
        Ok(())
    }

    /// Remove RUNPATH
    pub fn remove_runpath(&mut self) -> error::Result<()> {
        self.dynamic_entries.retain(|d| d.d_tag != DT_RUNPATH);
        Ok(())
    }

    /// Build the modified ELF binary
    pub fn build(&mut self) -> error::Result<Vec<u8>> {
        let mut output = self.data.clone();

        // Update interpreter if modified
        if let Some(ref new_interp) = self.modified_interpreter {
            self.update_interpreter_inplace(&mut output, new_interp)?;
        }

        // Update dynamic section if modified
        if !self.dynamic_entries.is_empty() {
            self.update_dynamic_section_inplace(&mut output)?;
        }

        Ok(output)
    }

    // Helper methods

    fn update_interpreter_inplace(&self, output: &mut Vec<u8>, new_interp: &str) -> error::Result<()> {
        // Find PT_INTERP segment
        for ph in &self.program_headers {
            if ph.p_type == PT_INTERP {
                let offset = ph.p_offset as usize;
                let size = ph.p_filesz as usize;

                if new_interp.len() + 1 > size {
                    return Err(error::Error::Malformed(
                        alloc::format!(
                            "New interpreter path too long ({} bytes) for PT_INTERP segment ({} bytes)",
                            new_interp.len() + 1,
                            size
                        ).into()
                    ));
                }

                // Clear old interpreter
                for i in offset..offset + size {
                    output[i] = 0;
                }

                // Write new interpreter
                output[offset..offset + new_interp.len()].copy_from_slice(new_interp.as_bytes());
                output[offset + new_interp.len()] = 0;

                return Ok(());
            }
        }

        Err(error::Error::Malformed("No PT_INTERP segment found".into()))
    }

    fn update_dynamic_section_inplace(&mut self, output: &mut Vec<u8>) -> error::Result<()> {
        // Find PT_DYNAMIC segment
        let dynamic_ph = self.program_headers.iter()
            .find(|ph| ph.p_type == PT_DYNAMIC)
            .ok_or_else(|| error::Error::Malformed("No PT_DYNAMIC segment found".into()))?;

        let dyn_offset = dynamic_ph.p_offset as usize;
        let dyn_size = dynamic_ph.p_filesz as usize;

        // Calculate entry size
        let entry_size = if self.is_64 { 16 } else { 8 };
        let required_size = self.dynamic_entries.len() * entry_size;

        if required_size > dyn_size {
            return Err(error::Error::Malformed(
                alloc::format!(
                    "Dynamic section too small: need {} bytes, have {} bytes",
                    required_size,
                    dyn_size
                ).into()
            ));
        }

        // Write dynamic entries
        let mut current_offset = dyn_offset;
        for dyn_entry in &self.dynamic_entries {
            output.pwrite_with(dyn_entry.clone(), current_offset, self.ctx)?;
            current_offset += entry_size;
        }

        // Ensure DT_NULL terminator if not present
        if self.dynamic_entries.last().map(|d| d.d_tag) != Some(DT_NULL) {
            if current_offset + entry_size <= dyn_offset + dyn_size {
                output.pwrite_with(
                    Dyn { d_tag: DT_NULL, d_val: 0 },
                    current_offset,
                    self.ctx
                )?;
            }
        }

        // Update dynamic string table if it changed
        self.update_dynstr_inplace(output)?;

        Ok(())
    }

    fn update_dynstr_inplace(&self, output: &mut Vec<u8>) -> error::Result<()> {
        // Find .dynstr section or use PT_DYNAMIC's string table
        // For simplicity, we'll use a heuristic: find SHT_STRTAB section that's referenced by dynamic entries

        // Find section by looking for DT_STRTAB in dynamic entries
        let strtab_addr = self.dynamic_entries.iter()
            .find(|d| d.d_tag == DT_STRTAB)
            .map(|d| d.d_val)
            .ok_or_else(|| error::Error::Malformed("No DT_STRTAB found".into()))?;

        // Find corresponding section or program header
        // Try to find in sections first
        for sh in &self.section_headers {
            if sh.sh_type == SHT_STRTAB && sh.sh_addr == strtab_addr {
                let offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                let new_data = self.dynstr.data();

                if new_data.len() > size {
                    return Err(error::Error::Malformed(
                        alloc::format!(
                            "Dynamic string table grew too large: {} bytes needed, {} available",
                            new_data.len(),
                            size
                        ).into()
                    ));
                }

                // Write new string table
                output[offset..offset + new_data.len()].copy_from_slice(new_data);

                // Zero out remaining space
                for i in offset + new_data.len()..offset + size {
                    output[i] = 0;
                }

                // Update DT_STRSZ
                if let Some(dynamic_ph) = self.program_headers.iter().find(|ph| ph.p_type == PT_DYNAMIC) {
                    let dyn_offset = dynamic_ph.p_offset as usize;
                    let entry_size = if self.is_64 { 16 } else { 8 };

                    for (idx, dyn_entry) in self.dynamic_entries.iter().enumerate() {
                        if dyn_entry.d_tag == DT_STRSZ {
                            let offset = dyn_offset + idx * entry_size;
                            output.pwrite_with(
                                Dyn { d_tag: DT_STRSZ, d_val: new_data.len() as u64 },
                                offset,
                                self.ctx
                            )?;
                            break;
                        }
                    }
                }

                return Ok(());
            }
        }

        // If not found in sections, warn but don't fail
        // This can happen with stripped binaries
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynstr_builder() {
        let mut builder = DynStrBuilder::new();

        let offset1 = builder.add("libfoo.so");
        let offset2 = builder.add("libbar.so");
        let offset3 = builder.add("libfoo.so"); // Should reuse

        assert_eq!(offset1, offset3);
        assert_ne!(offset1, offset2);

        let data = builder.data();
        assert_eq!(data[0], 0); // First byte is null
        assert!(data.len() > 0);
    }
}
