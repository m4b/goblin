//! High-level Mach-O writer and modifier
//!
//! This module provides utilities for modifying Mach-O binaries, including operations
//! similar to `install_name_tool`:
//! - Changing dylib install names (`change_id`)
//! - Changing dylib dependencies (`change_dylib`)
//! - Adding/removing/modifying rpaths
//! - Handling growing beyond slack space by relocating segments
//! - Removing code signatures

use crate::container;
use crate::error;
use crate::mach::load_command::*;
use crate::mach::header::{Header, filetype_to_str};
use crate::mach::constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_ARM64_32};
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;
use scroll::{Pwrite, Pread, ctx::TryIntoCtx, ctx::SizeWith};
use core::mem;

/// The kind of dylib dependency
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DylibKind {
    /// Normal dylib (LC_LOAD_DYLIB)
    Normal,
    /// Weak dylib (LC_LOAD_WEAK_DYLIB) - may be missing at runtime
    Weak,
    /// Re-exported dylib (LC_REEXPORT_DYLIB)
    Reexport,
    /// Lazy-loaded dylib (LC_LAZY_LOAD_DYLIB)
    Lazy,
    /// Upward dylib (LC_LOAD_UPWARD_DYLIB)
    Upward,
    /// This dylib's own identity (LC_ID_DYLIB)
    Id,
}

/// Information about a dylib dependency
#[derive(Debug, Clone)]
pub struct DylibInfo {
    /// The path/name of the dylib
    pub path: String,
    /// The kind of dylib reference
    pub kind: DylibKind,
    /// The current version of the dylib
    pub current_version: u32,
    /// The compatibility version of the dylib
    pub compatibility_version: u32,
    /// The timestamp
    pub timestamp: u32,
}

impl DylibInfo {
    /// Format the version as a human-readable string (e.g., "1.2.3")
    pub fn format_version(version: u32) -> String {
        let major = version >> 16;
        let minor = (version >> 8) & 0xff;
        let patch = version & 0xff;
        alloc::format!("{}.{}.{}", major, minor, patch)
    }

    /// Get current version as a formatted string
    pub fn current_version_string(&self) -> String {
        Self::format_version(self.current_version)
    }

    /// Get compatibility version as a formatted string
    pub fn compatibility_version_string(&self) -> String {
        Self::format_version(self.compatibility_version)
    }
}

/// Information about the Mach-O binary
#[derive(Debug, Clone)]
pub struct MachOInfo {
    /// CPU type (e.g., CPU_TYPE_X86_64, CPU_TYPE_ARM64)
    pub cputype: u32,
    /// CPU subtype
    pub cpusubtype: u32,
    /// File type (e.g., MH_EXECUTE, MH_DYLIB)
    pub filetype: u32,
    /// Whether this is a 64-bit binary
    pub is_64: bool,
    /// Number of load commands
    pub ncmds: usize,
    /// Size of load commands
    pub sizeofcmds: u32,
    /// Header flags
    pub flags: u32,
}

impl MachOInfo {
    /// Get the file type as a string
    pub fn filetype_string(&self) -> &'static str {
        filetype_to_str(self.filetype)
    }
}

/// A Mach-O file writer that can modify load commands and rebuild binaries
#[derive(Debug)]
pub struct MachOWriter {
    /// Original file data
    pub data: Vec<u8>,
    /// Parsed header
    pub header: Header,
    /// Load commands
    pub load_commands: Vec<LoadCommand>,
    /// Container context (endianness, 32/64-bit)
    pub ctx: container::Ctx,
    /// Strings for modified commands (index -> string)
    modified_strings: BTreeMap<usize, String>,
    /// Relocation delta when segments are relocated (0 if no relocation)
    relocation_delta: i64,
}

impl MachOWriter {
    /// Create a new writer from binary data
    pub fn new(data: Vec<u8>) -> error::Result<Self> {
        use crate::mach::*;

        let offset = 0;
        let (_, ctx_opt) = parse_magic_and_ctx(&data, offset)?;
        let ctx = ctx_opt.ok_or(error::Error::Malformed(
            "Invalid Mach-O magic".into()
        ))?;

        let header: Header = data.pread_with(offset, ctx)?;

        // Parse load commands
        let header_size = Header::size_with(&ctx);
        let mut cmd_offset = offset + header_size;
        let ncmds = header.ncmds;
        let mut cmds = Vec::new();

        for _ in 0..ncmds {
            let cmd = LoadCommand::parse(&data, &mut cmd_offset, ctx.le)?;
            cmds.push(cmd);
        }

        Ok(MachOWriter {
            data,
            header,
            load_commands: cmds,
            ctx,
            modified_strings: BTreeMap::new(),
            relocation_delta: 0,
        })
    }

    // ========== Inspection API ==========

    /// Get basic information about this Mach-O binary
    pub fn info(&self) -> MachOInfo {
        MachOInfo {
            cputype: self.header.cputype,
            cpusubtype: self.header.cpusubtype,
            filetype: self.header.filetype,
            is_64: self.ctx.container.is_big(),
            ncmds: self.header.ncmds,
            sizeofcmds: self.header.sizeofcmds,
            flags: self.header.flags,
        }
    }

    /// Get the install name (LC_ID_DYLIB) if this is a dylib
    pub fn get_id(&self) -> Option<String> {
        for (idx, cmd) in self.load_commands.iter().enumerate() {
            if let CommandVariant::IdDylib(dylib_cmd) = &cmd.command {
                // Check modified_strings first
                if let Some(s) = self.modified_strings.get(&idx) {
                    return Some(s.clone());
                }
                // Extract from original data
                let name_offset = cmd.offset + dylib_cmd.dylib.name as usize;
                if name_offset < self.data.len() {
                    if let Ok(s) = self.data.pread::<&str>(name_offset) {
                        return Some(s.into());
                    }
                }
            }
        }
        None
    }

    /// Get all dylib dependencies (including the ID if present)
    pub fn get_dylibs(&self) -> Vec<DylibInfo> {
        let mut dylibs = Vec::new();

        for (idx, cmd) in self.load_commands.iter().enumerate() {
            let (kind, dylib_cmd) = match &cmd.command {
                CommandVariant::IdDylib(dc) => (DylibKind::Id, dc),
                CommandVariant::LoadDylib(dc) => (DylibKind::Normal, dc),
                CommandVariant::LoadWeakDylib(dc) => (DylibKind::Weak, dc),
                CommandVariant::ReexportDylib(dc) => (DylibKind::Reexport, dc),
                CommandVariant::LazyLoadDylib(dc) => (DylibKind::Lazy, dc),
                CommandVariant::LoadUpwardDylib(dc) => (DylibKind::Upward, dc),
                _ => continue,
            };

            // Get the path - check modified_strings first
            let path = if let Some(s) = self.modified_strings.get(&idx) {
                s.clone()
            } else {
                let name_offset = cmd.offset + dylib_cmd.dylib.name as usize;
                if name_offset < self.data.len() {
                    self.data.pread::<&str>(name_offset)
                        .map(|s| s.to_string())
                        .unwrap_or_default()
                } else {
                    String::new()
                }
            };

            dylibs.push(DylibInfo {
                path,
                kind,
                current_version: dylib_cmd.dylib.current_version,
                compatibility_version: dylib_cmd.dylib.compatibility_version,
                timestamp: dylib_cmd.dylib.timestamp,
            });
        }

        dylibs
    }

    /// Get all rpaths
    pub fn get_rpaths(&self) -> Vec<String> {
        let mut rpaths = Vec::new();

        for (idx, cmd) in self.load_commands.iter().enumerate() {
            if let CommandVariant::Rpath(rpath_cmd) = &cmd.command {
                // Check modified_strings first
                let path = if let Some(s) = self.modified_strings.get(&idx) {
                    s.clone()
                } else {
                    let path_offset = cmd.offset + rpath_cmd.path as usize;
                    if path_offset < self.data.len() {
                        self.data.pread::<&str>(path_offset)
                            .map(|s| s.to_string())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    }
                };

                if !path.is_empty() {
                    rpaths.push(path);
                }
            }
        }

        rpaths
    }

    // ========== Modification API ==========

    /// Change the install name (LC_ID_DYLIB) of this dylib
    pub fn change_id(&mut self, new_name: &str) -> error::Result<()> {
        for (idx, cmd) in self.load_commands.iter_mut().enumerate() {
            if let CommandVariant::IdDylib(_) = cmd.command {
                cmd.command = Self::create_dylib_command_variant(LC_ID_DYLIB, new_name, 0, 0, 0)?;
                self.modified_strings.insert(idx, new_name.to_string());
                return Ok(());
            }
        }
        Err(error::Error::Malformed("No LC_ID_DYLIB found".into()))
    }

    /// Change a dylib dependency from old_name to new_name
    pub fn change_dylib(&mut self, old_name: &str, new_name: &str) -> error::Result<()> {
        let mut found = false;

        for (idx, cmd) in self.load_commands.iter_mut().enumerate() {
            let should_change = match &cmd.command {
                CommandVariant::LoadDylib(dylib_cmd)
                | CommandVariant::LoadWeakDylib(dylib_cmd)
                | CommandVariant::ReexportDylib(dylib_cmd)
                | CommandVariant::LazyLoadDylib(dylib_cmd) => {
                    // Read the path - check modified_strings first, then original data
                    let path = if let Some(s) = self.modified_strings.get(&idx) {
                        s.as_str()
                    } else {
                        let name_offset = cmd.offset + dylib_cmd.dylib.name as usize;
                        self.data.pread(name_offset)?
                    };
                    path == old_name
                }
                _ => false,
            };

            if should_change {
                let (cmd_type, timestamp, current_ver, compat_ver) = match &cmd.command {
                    CommandVariant::LoadDylib(dc) => (LC_LOAD_DYLIB, dc.dylib.timestamp,
                                                     dc.dylib.current_version, dc.dylib.compatibility_version),
                    CommandVariant::LoadWeakDylib(dc) => (LC_LOAD_WEAK_DYLIB, dc.dylib.timestamp,
                                                         dc.dylib.current_version, dc.dylib.compatibility_version),
                    CommandVariant::ReexportDylib(dc) => (LC_REEXPORT_DYLIB, dc.dylib.timestamp,
                                                         dc.dylib.current_version, dc.dylib.compatibility_version),
                    CommandVariant::LazyLoadDylib(dc) => (LC_LAZY_LOAD_DYLIB, dc.dylib.timestamp,
                                                         dc.dylib.current_version, dc.dylib.compatibility_version),
                    _ => unreachable!(),
                };

                cmd.command = Self::create_dylib_command_variant(cmd_type, new_name, timestamp, current_ver, compat_ver)?;
                self.modified_strings.insert(idx, new_name.to_string());
                found = true;
            }
        }

        if !found {
            return Err(error::Error::Malformed(
                alloc::format!("Dylib '{}' not found", old_name).into()
            ));
        }

        Ok(())
    }

    /// Delete a dylib dependency by path
    pub fn delete_dylib(&mut self, path: &str) -> error::Result<()> {
        let mut found_idx = None;

        for (idx, cmd) in self.load_commands.iter().enumerate() {
            let matches = match &cmd.command {
                CommandVariant::LoadDylib(dylib_cmd)
                | CommandVariant::LoadWeakDylib(dylib_cmd)
                | CommandVariant::ReexportDylib(dylib_cmd)
                | CommandVariant::LazyLoadDylib(dylib_cmd)
                | CommandVariant::LoadUpwardDylib(dylib_cmd) => {
                    // Check modified_strings first
                    let existing_path = if let Some(s) = self.modified_strings.get(&idx) {
                        s.as_str()
                    } else {
                        let name_offset = cmd.offset + dylib_cmd.dylib.name as usize;
                        if name_offset < self.data.len() {
                            self.data.pread::<&str>(name_offset).unwrap_or("")
                        } else {
                            ""
                        }
                    };
                    existing_path == path
                }
                _ => false,
            };

            if matches {
                found_idx = Some(idx);
                break;
            }
        }

        if let Some(idx) = found_idx {
            self.load_commands.remove(idx);
            self.modified_strings.remove(&idx);
            // Shift all indices after the removed one
            let keys_to_update: Vec<_> = self.modified_strings.keys().filter(|&&k| k > idx).copied().collect();
            for key in keys_to_update {
                if let Some(value) = self.modified_strings.remove(&key) {
                    self.modified_strings.insert(key - 1, value);
                }
            }
            Ok(())
        } else {
            Err(error::Error::Malformed(
                alloc::format!("Dylib '{}' not found", path).into()
            ))
        }
    }

    /// Add a new dylib dependency
    ///
    /// Note: This is not a standard `install_name_tool` feature but is useful for binary patching.
    pub fn add_dylib(&mut self, path: &str, kind: DylibKind) -> error::Result<()> {
        // Check if it already exists
        for (idx, cmd) in self.load_commands.iter().enumerate() {
            let existing_path = match &cmd.command {
                CommandVariant::LoadDylib(dylib_cmd)
                | CommandVariant::LoadWeakDylib(dylib_cmd)
                | CommandVariant::ReexportDylib(dylib_cmd)
                | CommandVariant::LazyLoadDylib(dylib_cmd)
                | CommandVariant::LoadUpwardDylib(dylib_cmd) => {
                    if let Some(s) = self.modified_strings.get(&idx) {
                        Some(s.as_str())
                    } else {
                        let name_offset = cmd.offset + dylib_cmd.dylib.name as usize;
                        if name_offset < self.data.len() {
                            self.data.pread::<&str>(name_offset).ok()
                        } else {
                            None
                        }
                    }
                }
                _ => None,
            };

            if existing_path == Some(path) {
                return Err(error::Error::Malformed(
                    alloc::format!("Dylib '{}' already exists", path).into()
                ));
            }
        }

        let cmd_type = match kind {
            DylibKind::Normal => LC_LOAD_DYLIB,
            DylibKind::Weak => LC_LOAD_WEAK_DYLIB,
            DylibKind::Reexport => LC_REEXPORT_DYLIB,
            DylibKind::Lazy => LC_LAZY_LOAD_DYLIB,
            DylibKind::Upward => LC_LOAD_UPWARD_DYLIB,
            DylibKind::Id => {
                return Err(error::Error::Malformed(
                    "Cannot add LC_ID_DYLIB via add_dylib, use change_id instead".into()
                ));
            }
        };

        let command = Self::create_dylib_command_variant(
            cmd_type,
            path,
            0,         // timestamp
            0x10000,   // current_version (1.0.0)
            0x10000,   // compatibility_version (1.0.0)
        )?;

        let new_idx = self.load_commands.len();
        self.load_commands.push(LoadCommand {
            offset: 0,  // will be recalculated
            command,
        });
        self.modified_strings.insert(new_idx, path.to_string());
        Ok(())
    }

    /// Add an rpath
    pub fn add_rpath(&mut self, path: &str) -> error::Result<()> {
        // Check if it already exists
        for (idx, cmd) in self.load_commands.iter().enumerate() {
            if let CommandVariant::Rpath(rpath_cmd) = &cmd.command {
                let existing_path = if let Some(s) = self.modified_strings.get(&idx) {
                    s.as_str()
                } else {
                    let name_offset = cmd.offset + rpath_cmd.path as usize;
                    self.data.pread(name_offset)?
                };
                if existing_path == path {
                    return Err(error::Error::Malformed(
                        alloc::format!("Rpath '{}' already exists", path).into()
                    ));
                }
            }
        }

        let command = Self::create_rpath_command_variant(path)?;
        let new_idx = self.load_commands.len();
        self.load_commands.push(LoadCommand {
            offset: 0,  // will be recalculated
            command,
        });
        self.modified_strings.insert(new_idx, path.to_string());
        Ok(())
    }

    /// Delete an rpath
    pub fn delete_rpath(&mut self, path: &str) -> error::Result<()> {
        let mut found_idx = None;

        for (idx, cmd) in self.load_commands.iter().enumerate() {
            if let CommandVariant::Rpath(rpath_cmd) = &cmd.command {
                let existing_path = if let Some(s) = self.modified_strings.get(&idx) {
                    s.as_str()
                } else {
                    let name_offset = cmd.offset + rpath_cmd.path as usize;
                    self.data.pread(name_offset)?
                };
                if existing_path == path {
                    found_idx = Some(idx);
                    break;
                }
            }
        }

        if let Some(idx) = found_idx {
            self.load_commands.remove(idx);
            self.modified_strings.remove(&idx);
            // Shift all indices after the removed one
            let keys_to_update: Vec<_> = self.modified_strings.keys().filter(|&&k| k > idx).copied().collect();
            for key in keys_to_update {
                if let Some(value) = self.modified_strings.remove(&key) {
                    self.modified_strings.insert(key - 1, value);
                }
            }
            Ok(())
        } else {
            Err(error::Error::Malformed(
                alloc::format!("Rpath '{}' not found", path).into()
            ))
        }
    }

    /// Change an rpath from old_path to new_path
    pub fn change_rpath(&mut self, old_path: &str, new_path: &str) -> error::Result<()> {
        for (idx, cmd) in self.load_commands.iter_mut().enumerate() {
            if let CommandVariant::Rpath(rpath_cmd) = &cmd.command {
                let existing_path = if let Some(s) = self.modified_strings.get(&idx) {
                    s.as_str()
                } else {
                    let name_offset = cmd.offset + rpath_cmd.path as usize;
                    self.data.pread(name_offset)?
                };
                if existing_path == old_path {
                    cmd.command = Self::create_rpath_command_variant(new_path)?;
                    self.modified_strings.insert(idx, new_path.to_string());
                    return Ok(());
                }
            }
        }

        Err(error::Error::Malformed(
            alloc::format!("Rpath '{}' not found", old_path).into()
        ))
    }

    /// Remove code signature (it becomes invalid after modification)
    pub fn remove_code_signature(&mut self) {
        // Find all code signature indices first
        let mut indices_to_remove: Vec<usize> = self.load_commands
            .iter()
            .enumerate()
            .filter(|(_, cmd)| matches!(cmd.command, CommandVariant::CodeSignature(_)))
            .map(|(idx, _)| idx)
            .collect();

        // Remove in reverse order to maintain index validity
        indices_to_remove.sort_by(|a, b| b.cmp(a));

        for idx in indices_to_remove {
            self.load_commands.remove(idx);
            self.modified_strings.remove(&idx);

            // Shift all indices after the removed one
            let keys_to_update: Vec<_> = self.modified_strings
                .keys()
                .filter(|&&k| k > idx)
                .copied()
                .collect();

            for key in keys_to_update {
                if let Some(value) = self.modified_strings.remove(&key) {
                    self.modified_strings.insert(key - 1, value);
                }
            }
        }
    }

    /// Build the modified Mach-O binary
    pub fn build(&mut self) -> error::Result<Vec<u8>> {
        // Remove code signature first as it will be invalid
        self.remove_code_signature();

        // Calculate new load commands size
        let new_sizeofcmds = self.calculate_load_commands_size();
        let header_size = Header::size_with(&self.ctx);
        let load_commands_end = header_size + new_sizeofcmds;

        // Find where actual data starts (first section offset)
        let first_data_offset = self.find_first_data_offset();

        // Original load commands end - this is where we'll copy data from if not relocating
        let _original_commands_end = header_size + self.header.sizeofcmds as usize;

        // Check if we need to relocate segments (new commands don't fit in available space)
        let needs_relocation = load_commands_end > first_data_offset;

        if needs_relocation {
            self.relocate_segments(load_commands_end)?;
        }

        // Build the output buffer
        let mut output = Vec::new();

        // Update header
        let mut header = self.header;
        header.ncmds = self.load_commands.len();
        header.sizeofcmds = new_sizeofcmds as u32;

        // Write header
        let header_bytes = self.serialize_header(&header)?;
        output.extend_from_slice(&header_bytes);

        // Write load commands
        let lc_bytes = self.serialize_load_commands()?;
        output.extend_from_slice(&lc_bytes);

        // Copy segment data
        if needs_relocation {
            // Align to page boundary
            let page_size = self.page_size();
            let current_size = output.len();
            let padding_size = (page_size - (current_size % page_size)) % page_size;
            output.resize(output.len() + padding_size, 0);

            // Copy relocated segments from original first data offset
            if first_data_offset < self.data.len() {
                output.extend_from_slice(&self.data[first_data_offset..]);
            }
        } else {
            // No relocation needed - new commands fit in existing slack space
            // Data must stay at its original offset, so pad to reach first_data_offset
            if output.len() < first_data_offset {
                // Pad with zeros to reach where original data starts
                output.resize(first_data_offset, 0);
            }
            // Copy data from its original location (it stays at the same offset)
            if first_data_offset < self.data.len() {
                output.extend_from_slice(&self.data[first_data_offset..]);
            }
        }

        Ok(output)
    }

    // Helper methods

    fn create_dylib_command_variant(
        cmd_type: u32,
        name: &str,
        timestamp: u32,
        current_version: u32,
        compatibility_version: u32,
    ) -> error::Result<CommandVariant> {
        let name_bytes = name.as_bytes();
        let name_offset = SIZEOF_DYLIB_COMMAND as u32;
        let cmdsize = (SIZEOF_DYLIB_COMMAND + name_bytes.len() + 1 + 7) & !7; // Align to 8 bytes

        let dylib_cmd = DylibCommand {
            cmd: cmd_type,
            cmdsize: cmdsize as u32,
            dylib: Dylib {
                name: name_offset,
                timestamp,
                current_version,
                compatibility_version,
            },
        };

        match cmd_type {
            LC_ID_DYLIB => Ok(CommandVariant::IdDylib(dylib_cmd)),
            LC_LOAD_DYLIB => Ok(CommandVariant::LoadDylib(dylib_cmd)),
            LC_LOAD_WEAK_DYLIB => Ok(CommandVariant::LoadWeakDylib(dylib_cmd)),
            LC_REEXPORT_DYLIB => Ok(CommandVariant::ReexportDylib(dylib_cmd)),
            LC_LAZY_LOAD_DYLIB => Ok(CommandVariant::LazyLoadDylib(dylib_cmd)),
            LC_LOAD_UPWARD_DYLIB => Ok(CommandVariant::LoadUpwardDylib(dylib_cmd)),
            _ => Err(error::Error::Malformed("Invalid dylib command type".into())),
        }
    }

    fn create_rpath_command_variant(path: &str) -> error::Result<CommandVariant> {
        let path_bytes = path.as_bytes();
        let path_offset = SIZEOF_RPATH_COMMAND as u32;
        let cmdsize = (SIZEOF_RPATH_COMMAND + path_bytes.len() + 1 + 7) & !7; // Align to 8 bytes

        let rpath_cmd = RpathCommand {
            cmd: LC_RPATH,
            cmdsize: cmdsize as u32,
            path: path_offset,
        };

        Ok(CommandVariant::Rpath(rpath_cmd))
    }

    fn calculate_load_commands_size(&self) -> usize {
        self.load_commands.iter().map(|cmd| cmd.command.cmdsize()).sum()
    }

    fn find_first_segment_offset(&self) -> usize {
        for cmd in &self.load_commands {
            match &cmd.command {
                CommandVariant::Segment32(seg) => {
                    if seg.fileoff > 0 {
                        return seg.fileoff as usize;
                    }
                }
                CommandVariant::Segment64(seg) => {
                    if seg.fileoff > 0 {
                        return seg.fileoff as usize;
                    }
                }
                _ => {}
            }
        }
        // Default to header + original sizeofcmds
        Header::size_with(&self.ctx) + self.header.sizeofcmds as usize
    }

    /// Find the offset where actual data starts (minimum section offset or segment data offset)
    /// This is used to determine available slack space for load commands
    fn find_first_data_offset(&self) -> usize {
        let header_size = Header::size_with(&self.ctx);
        let mut min_offset = usize::MAX;

        for cmd in &self.load_commands {
            match &cmd.command {
                CommandVariant::Segment32(seg) => {
                    // For segments with file data, check their sections
                    if seg.filesize > 0 {
                        // Parse sections from original data to find their offsets
                        let sections_start = cmd.offset + SIZEOF_SEGMENT_COMMAND_32;
                        for i in 0..seg.nsects as usize {
                            let section_offset = sections_start + i * SIZEOF_SECTION_32;
                            if section_offset + SIZEOF_SECTION_32 <= self.data.len() {
                                if let Ok(section) = self.data.pread_with::<Section32>(section_offset, self.ctx.le) {
                                    // Only consider sections with actual file data (not zerofill)
                                    if section.offset > 0 && section.size > 0 {
                                        min_offset = min_offset.min(section.offset as usize);
                                    }
                                }
                            }
                        }
                    }
                }
                CommandVariant::Segment64(seg) => {
                    if seg.filesize > 0 {
                        let sections_start = cmd.offset + SIZEOF_SEGMENT_COMMAND_64;
                        for i in 0..seg.nsects as usize {
                            let section_offset = sections_start + i * SIZEOF_SECTION_64;
                            if section_offset + SIZEOF_SECTION_64 <= self.data.len() {
                                if let Ok(section) = self.data.pread_with::<Section64>(section_offset, self.ctx.le) {
                                    if section.offset > 0 && section.size > 0 {
                                        min_offset = min_offset.min(section.offset as usize);
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // If no sections found, fall back to segment-based offset or header + sizeofcmds
        if min_offset == usize::MAX {
            let segment_offset = self.find_first_segment_offset();
            if segment_offset > header_size {
                segment_offset
            } else {
                header_size + self.header.sizeofcmds as usize
            }
        } else {
            min_offset
        }
    }

    /// Get the page size for this binary's CPU type
    /// ARM64 uses 16KB pages, x86/x86_64 use 4KB pages
    fn page_size(&self) -> usize {
        match self.header.cputype {
            CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => 16384,  // 16KB for Apple Silicon
            _ => 4096,  // 4KB for Intel and others
        }
    }

    fn relocate_segments(&mut self, new_offset: usize) -> error::Result<()> {
        // Round up to page boundary
        let page_size = self.page_size();
        let aligned_offset = ((new_offset + page_size - 1) / page_size) * page_size;

        let first_data_offset = self.find_first_data_offset();
        let delta = aligned_offset as i64 - first_data_offset as i64;

        if delta == 0 {
            return Ok(());
        }

        // Store delta for use during serialization (for updating section offsets)
        self.relocation_delta = delta;

        // Update all segment and section offsets
        for cmd in &mut self.load_commands {
            match &mut cmd.command {
                CommandVariant::Segment32(seg) => {
                    if seg.fileoff > 0 {
                        seg.fileoff = (seg.fileoff as i64 + delta) as u32;
                    }
                }
                CommandVariant::Segment64(seg) => {
                    if seg.fileoff > 0 {
                        seg.fileoff = (seg.fileoff as i64 + delta) as u64;
                    }
                }
                CommandVariant::Symtab(symtab) => {
                    if symtab.symoff > 0 {
                        symtab.symoff = (symtab.symoff as i64 + delta) as u32;
                    }
                    if symtab.stroff > 0 {
                        symtab.stroff = (symtab.stroff as i64 + delta) as u32;
                    }
                }
                CommandVariant::Dysymtab(dysymtab) => {
                    if dysymtab.tocoff > 0 {
                        dysymtab.tocoff = (dysymtab.tocoff as i64 + delta) as u32;
                    }
                    if dysymtab.modtaboff > 0 {
                        dysymtab.modtaboff = (dysymtab.modtaboff as i64 + delta) as u32;
                    }
                    if dysymtab.extrefsymoff > 0 {
                        dysymtab.extrefsymoff = (dysymtab.extrefsymoff as i64 + delta) as u32;
                    }
                    if dysymtab.indirectsymoff > 0 {
                        dysymtab.indirectsymoff = (dysymtab.indirectsymoff as i64 + delta) as u32;
                    }
                    if dysymtab.extreloff > 0 {
                        dysymtab.extreloff = (dysymtab.extreloff as i64 + delta) as u32;
                    }
                    if dysymtab.locreloff > 0 {
                        dysymtab.locreloff = (dysymtab.locreloff as i64 + delta) as u32;
                    }
                }
                CommandVariant::DyldInfo(dyld_info) | CommandVariant::DyldInfoOnly(dyld_info) => {
                    if dyld_info.rebase_off > 0 {
                        dyld_info.rebase_off = (dyld_info.rebase_off as i64 + delta) as u32;
                    }
                    if dyld_info.bind_off > 0 {
                        dyld_info.bind_off = (dyld_info.bind_off as i64 + delta) as u32;
                    }
                    if dyld_info.weak_bind_off > 0 {
                        dyld_info.weak_bind_off = (dyld_info.weak_bind_off as i64 + delta) as u32;
                    }
                    if dyld_info.lazy_bind_off > 0 {
                        dyld_info.lazy_bind_off = (dyld_info.lazy_bind_off as i64 + delta) as u32;
                    }
                    if dyld_info.export_off > 0 {
                        dyld_info.export_off = (dyld_info.export_off as i64 + delta) as u32;
                    }
                }
                CommandVariant::EncryptionInfo32(enc) => {
                    if enc.cryptoff > 0 {
                        enc.cryptoff = (enc.cryptoff as i64 + delta) as u32;
                    }
                }
                CommandVariant::EncryptionInfo64(enc) => {
                    if enc.cryptoff > 0 {
                        enc.cryptoff = (enc.cryptoff as i64 + delta) as u32;
                    }
                }
                CommandVariant::CodeSignature(linkedit)
                | CommandVariant::SegmentSplitInfo(linkedit)
                | CommandVariant::FunctionStarts(linkedit)
                | CommandVariant::DataInCode(linkedit)
                | CommandVariant::DylibCodeSignDrs(linkedit)
                | CommandVariant::LinkerOptimizationHint(linkedit)
                | CommandVariant::DyldExportsTrie(linkedit)
                | CommandVariant::DyldChainedFixups(linkedit) => {
                    if linkedit.dataoff > 0 {
                        linkedit.dataoff = (linkedit.dataoff as i64 + delta) as u32;
                    }
                }
                CommandVariant::Note(note) => {
                    if note.offset > 0 {
                        note.offset = (note.offset as i64 + delta) as u64;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn serialize_header(&self, header: &Header) -> error::Result<Vec<u8>> {
        let header_size = Header::size_with(&self.ctx);
        let mut buf = vec![0u8; header_size];
        header.try_into_ctx(&mut buf[..], self.ctx)?;
        Ok(buf)
    }

    fn serialize_load_commands(&mut self) -> error::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut current_offset = Header::size_with(&self.ctx);

        // Serialize all commands first
        let serialized_commands: error::Result<Vec<_>> = (0..self.load_commands.len())
            .map(|idx| self.serialize_load_command_at_index(idx))
            .collect();
        let serialized_commands = serialized_commands?;

        // Now update offsets and build buffer
        for (idx, cmd_bytes) in serialized_commands.iter().enumerate() {
            self.load_commands[idx].offset = current_offset;
            buf.extend_from_slice(cmd_bytes);
            current_offset += cmd_bytes.len();
        }

        Ok(buf)
    }

    fn serialize_load_command_at_index(&self, idx: usize) -> error::Result<Vec<u8>> {
        let cmd = &self.load_commands[idx].command;
        let size = cmd.cmdsize();
        let mut buf = vec![0u8; size];

        match cmd {
            CommandVariant::IdDylib(dc)
            | CommandVariant::LoadDylib(dc)
            | CommandVariant::LoadWeakDylib(dc)
            | CommandVariant::ReexportDylib(dc)
            | CommandVariant::LazyLoadDylib(dc)
            | CommandVariant::LoadUpwardDylib(dc) => {
                buf.pwrite_with(dc, 0, self.ctx.le)?;
                let name_offset = dc.dylib.name as usize;

                // Extract the name
                let name = self.extract_lc_str_for_index(idx)?;
                let name_bytes = name.as_bytes();

                buf[name_offset..name_offset + name_bytes.len()].copy_from_slice(name_bytes);
                buf[name_offset + name_bytes.len()] = 0; // null terminator
            }
            CommandVariant::Rpath(rc) => {
                buf.pwrite_with(rc, 0, self.ctx.le)?;
                let path_offset = rc.path as usize;

                let path = self.extract_lc_str_for_index(idx)?;
                let path_bytes = path.as_bytes();

                buf[path_offset..path_offset + path_bytes.len()].copy_from_slice(path_bytes);
                buf[path_offset + path_bytes.len()] = 0; // null terminator
            }
            CommandVariant::Segment32(seg) => {
                // Copy from original data first (includes sections)
                let orig_cmd = &self.load_commands[idx];
                if orig_cmd.offset > 0 && orig_cmd.offset + size <= self.data.len() {
                    buf.copy_from_slice(&self.data[orig_cmd.offset..orig_cmd.offset + size]);
                }
                // Write updated segment command
                buf.pwrite_with(seg, 0, self.ctx.le)?;
                // Update section offsets if relocating
                if self.relocation_delta != 0 {
                    self.update_section_offsets_32(&mut buf, seg.nsects)?;
                }
            }
            CommandVariant::Segment64(seg) => {
                // Copy from original data first (includes sections)
                let orig_cmd = &self.load_commands[idx];
                if orig_cmd.offset > 0 && orig_cmd.offset + size <= self.data.len() {
                    buf.copy_from_slice(&self.data[orig_cmd.offset..orig_cmd.offset + size]);
                }
                // Write updated segment command
                buf.pwrite_with(seg, 0, self.ctx.le)?;
                // Update section offsets if relocating
                if self.relocation_delta != 0 {
                    self.update_section_offsets_64(&mut buf, seg.nsects)?;
                }
            }
            _ => {
                // For other commands, copy from original data
                let orig_cmd = &self.load_commands[idx];
                if orig_cmd.offset > 0 && orig_cmd.offset + size <= self.data.len() {
                    buf.copy_from_slice(&self.data[orig_cmd.offset..orig_cmd.offset + size]);
                    return Ok(buf);
                }
                // If not found in original, try to serialize with pwrite
                cmd.pwrite_into(&mut buf, self.ctx.le)?;
            }
        }

        Ok(buf)
    }

    /// Update section offsets in a 32-bit segment command buffer
    fn update_section_offsets_32(&self, buf: &mut [u8], nsects: u32) -> error::Result<()> {
        let delta = self.relocation_delta;
        let section_start = SIZEOF_SEGMENT_COMMAND_32;

        for i in 0..nsects as usize {
            let section_offset = section_start + i * SIZEOF_SECTION_32;

            // Read section from buffer
            let mut section: Section32 = buf.pread_with(section_offset, self.ctx.le)?;

            // Update offset if non-zero (zero means zerofill section)
            if section.offset > 0 {
                section.offset = (section.offset as i64 + delta) as u32;
            }

            // Update reloff if non-zero
            if section.reloff > 0 {
                section.reloff = (section.reloff as i64 + delta) as u32;
            }

            // Write back
            buf.pwrite_with(section, section_offset, self.ctx.le)?;
        }

        Ok(())
    }

    /// Update section offsets in a 64-bit segment command buffer
    fn update_section_offsets_64(&self, buf: &mut [u8], nsects: u32) -> error::Result<()> {
        let delta = self.relocation_delta;
        let section_start = SIZEOF_SEGMENT_COMMAND_64;

        for i in 0..nsects as usize {
            let section_offset = section_start + i * SIZEOF_SECTION_64;

            // Read section from buffer
            let mut section: Section64 = buf.pread_with(section_offset, self.ctx.le)?;

            // Update offset if non-zero (zero means zerofill section)
            if section.offset > 0 {
                section.offset = (section.offset as i64 + delta) as u32;
            }

            // Update reloff if non-zero
            if section.reloff > 0 {
                section.reloff = (section.reloff as i64 + delta) as u32;
            }

            // Write back
            buf.pwrite_with(section, section_offset, self.ctx.le)?;
        }

        Ok(())
    }

    fn extract_lc_str_for_index(&self, idx: usize) -> error::Result<String> {
        // Check modified_strings first
        if let Some(s) = self.modified_strings.get(&idx) {
            return Ok(s.clone());
        }

        // Otherwise, extract from original data
        let cmd = &self.load_commands[idx];
        match &cmd.command {
            CommandVariant::IdDylib(dc)
            | CommandVariant::LoadDylib(dc)
            | CommandVariant::LoadWeakDylib(dc)
            | CommandVariant::ReexportDylib(dc)
            | CommandVariant::LazyLoadDylib(dc)
            | CommandVariant::LoadUpwardDylib(dc) => {
                let name_offset = cmd.offset + dc.dylib.name as usize;
                if name_offset < self.data.len() {
                    let s: &str = self.data.pread(name_offset)?;
                    return Ok(s.into());
                }
            }
            CommandVariant::Rpath(rc) => {
                let path_offset = cmd.offset + rc.path as usize;
                if path_offset < self.data.len() {
                    let s: &str = self.data.pread(path_offset)?;
                    return Ok(s.into());
                }
            }
            _ => {}
        }

        Err(error::Error::Malformed("Cannot extract LC string".into()))
    }
}

impl CommandVariant {
    /// Write this command variant to a buffer using pwrite
    /// Returns Ok(()) if successful, Err if this command type doesn't support pwrite
    fn pwrite_into(&self, buf: &mut [u8], le: scroll::Endian) -> error::Result<()> {
        match self {
            CommandVariant::Segment32(s) => { buf.pwrite_with(s, 0, le)?; }
            CommandVariant::Segment64(s) => { buf.pwrite_with(s, 0, le)?; }
            CommandVariant::Symtab(s) => { buf.pwrite_with(s, 0, le)?; }
            CommandVariant::Dysymtab(d) => { buf.pwrite_with(d, 0, le)?; }
            CommandVariant::Uuid(u) => { buf.pwrite_with(u, 0, le)?; }
            CommandVariant::VersionMinMacosx(v)
            | CommandVariant::VersionMinIphoneos(v)
            | CommandVariant::VersionMinTvos(v)
            | CommandVariant::VersionMinWatchos(v) => { buf.pwrite_with(v, 0, le)?; }
            CommandVariant::SourceVersion(s) => { buf.pwrite_with(s, 0, le)?; }
            CommandVariant::Main(e) => { buf.pwrite_with(e, 0, le)?; }
            CommandVariant::DyldInfo(d) | CommandVariant::DyldInfoOnly(d) => { buf.pwrite_with(d, 0, le)?; }
            CommandVariant::BuildVersion(b) => { buf.pwrite_with(b, 0, le)?; }
            CommandVariant::PreboundDylib(p) => { buf.pwrite_with(p, 0, le)?; }
            CommandVariant::Routines32(r) => { buf.pwrite_with(r, 0, le)?; }
            CommandVariant::Routines64(r) => { buf.pwrite_with(r, 0, le)?; }
            CommandVariant::SubFramework(s) => { buf.pwrite_with(s, 0, le)?; }
            CommandVariant::SubUmbrella(s) => { buf.pwrite_with(s, 0, le)?; }
            CommandVariant::SubClient(s) => { buf.pwrite_with(s, 0, le)?; }
            CommandVariant::SubLibrary(s) => { buf.pwrite_with(s, 0, le)?; }
            CommandVariant::TwolevelHints(t) => { buf.pwrite_with(t, 0, le)?; }
            CommandVariant::PrebindCksum(p) => { buf.pwrite_with(p, 0, le)?; }
            CommandVariant::CodeSignature(l)
            | CommandVariant::SegmentSplitInfo(l)
            | CommandVariant::FunctionStarts(l)
            | CommandVariant::DataInCode(l)
            | CommandVariant::DylibCodeSignDrs(l)
            | CommandVariant::LinkerOptimizationHint(l)
            | CommandVariant::DyldExportsTrie(l)
            | CommandVariant::LinkerOption(l)
            | CommandVariant::DyldChainedFixups(l) => { buf.pwrite_with(l, 0, le)?; }
            CommandVariant::EncryptionInfo32(e) => { buf.pwrite_with(e, 0, le)?; }
            CommandVariant::EncryptionInfo64(e) => { buf.pwrite_with(e, 0, le)?; }
            CommandVariant::Note(n) => { buf.pwrite_with(n, 0, le)?; }
            CommandVariant::FilesetEntry(f) => { buf.pwrite_with(f, 0, le)?; }
            CommandVariant::LoadFvmlib(f) | CommandVariant::IdFvmlib(f) => { buf.pwrite_with(f, 0, le)?; }
            CommandVariant::Fvmfile(f) => { buf.pwrite_with(f, 0, le)?; }
            CommandVariant::Symseg(s) => { buf.pwrite_with(s, 0, le)?; }
            CommandVariant::Ident(i) => { buf.pwrite_with(i, 0, le)?; }
            CommandVariant::Prepage(p) => { buf.pwrite_with(p, 0, le)?; }
            CommandVariant::LoadUpwardDylib(u) => { buf.pwrite_with(u, 0, le)?; }
            CommandVariant::Unimplemented(h) => { buf.pwrite_with(h, 0, le)?; }
            // Commands that don't implement Pwrite or are handled specially
            // These should have been handled by copying from original data
            _ => {
                return Err(error::Error::Malformed("Command must be copied from original data".into()));
            }
        }
        Ok(())
    }
}

/// Handle fat/universal binaries (both 32-bit and 64-bit fat headers)
pub fn modify_fat_binary<F>(data: Vec<u8>, mut modifier: F) -> error::Result<Vec<u8>>
where
    F: FnMut(&mut MachOWriter) -> error::Result<()>,
{
    use crate::mach::fat::*;

    // Check if it's a fat binary
    let magic = data.pread_with::<u32>(0, scroll::BE)?;

    let is_fat64 = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
    let is_fat32 = magic == FAT_MAGIC || magic == FAT_CIGAM;

    if !is_fat64 && !is_fat32 {
        // Not a fat binary, process as single arch
        let mut writer = MachOWriter::new(data)?;
        modifier(&mut writer)?;
        return writer.build();
    }

    // Parse fat header
    let header = FatHeader::parse(&data)?;
    let mut output = Vec::new();

    // Write fat header
    output.extend_from_slice(&data[0..mem::size_of::<FatHeader>()]);

    if is_fat64 {
        // 64-bit fat binary
        modify_fat_binary_64(&data, &header, &mut output, &mut modifier)
    } else {
        // 32-bit fat binary
        modify_fat_binary_32(&data, &header, &mut output, &mut modifier)
    }
}

/// Process 32-bit fat binary
fn modify_fat_binary_32<F>(
    data: &[u8],
    header: &crate::mach::fat::FatHeader,
    output: &mut Vec<u8>,
    modifier: &mut F,
) -> error::Result<Vec<u8>>
where
    F: FnMut(&mut MachOWriter) -> error::Result<()>,
{
    use crate::mach::fat::*;

    // Parse and modify each arch
    let mut arch_data = Vec::new();
    for i in 0..header.nfat_arch {
        let arch_offset = mem::size_of::<FatHeader>() + i as usize * mem::size_of::<FatArch>();
        let arch: FatArch = data.pread_with(arch_offset, scroll::BE)?;

        // Extract this arch's data
        let arch_bytes = data[arch.offset as usize..(arch.offset + arch.size) as usize].to_vec();

        // Modify it
        let mut writer = MachOWriter::new(arch_bytes)?;
        modifier(&mut writer)?;
        let modified = writer.build()?;

        arch_data.push((arch, modified));
    }

    // Calculate new offsets and write arch headers
    let mut current_offset = mem::size_of::<FatHeader>() + header.nfat_arch as usize * mem::size_of::<FatArch>();
    // Align to 4096
    current_offset = ((current_offset + 4095) / 4096) * 4096;

    for (arch, modified_data) in &mut arch_data {
        arch.offset = current_offset as u32;
        arch.size = modified_data.len() as u32;

        let mut arch_bytes = [0u8; mem::size_of::<FatArch>()];
        arch_bytes.pwrite_with(*arch, 0, scroll::BE)?;
        output.extend_from_slice(&arch_bytes);

        current_offset = ((current_offset + modified_data.len() + 4095) / 4096) * 4096;
    }

    // Pad to first arch offset
    while output.len() < arch_data[0].0.offset as usize {
        output.push(0);
    }

    // Write arch data
    for (arch, modified_data) in &arch_data {
        // Pad to offset
        while output.len() < arch.offset as usize {
            output.push(0);
        }
        output.extend_from_slice(modified_data);
    }

    Ok(output.clone())
}

/// Process 64-bit fat binary
fn modify_fat_binary_64<F>(
    data: &[u8],
    header: &crate::mach::fat::FatHeader,
    output: &mut Vec<u8>,
    modifier: &mut F,
) -> error::Result<Vec<u8>>
where
    F: FnMut(&mut MachOWriter) -> error::Result<()>,
{
    use crate::mach::fat::*;

    // Parse and modify each arch
    let mut arch_data = Vec::new();
    for i in 0..header.nfat_arch {
        let arch_offset = mem::size_of::<FatHeader>() + i as usize * SIZEOF_FAT_ARCH_64;
        let arch: FatArch64 = data.pread_with(arch_offset, scroll::BE)?;

        // Extract this arch's data
        let start = arch.offset as usize;
        let end = start + arch.size as usize;
        if end > data.len() {
            return Err(error::Error::Malformed("FatArch64 offset/size out of bounds".into()));
        }
        let arch_bytes = data[start..end].to_vec();

        // Modify it
        let mut writer = MachOWriter::new(arch_bytes)?;
        modifier(&mut writer)?;
        let modified = writer.build()?;

        arch_data.push((arch, modified));
    }

    // Calculate new offsets and write arch headers
    let mut current_offset = mem::size_of::<FatHeader>() + header.nfat_arch as usize * SIZEOF_FAT_ARCH_64;
    // Align to 4096
    current_offset = ((current_offset + 4095) / 4096) * 4096;

    for (arch, modified_data) in &mut arch_data {
        arch.offset = current_offset as u64;
        arch.size = modified_data.len() as u64;

        let mut arch_bytes = [0u8; SIZEOF_FAT_ARCH_64];
        arch_bytes.pwrite_with(*arch, 0, scroll::BE)?;
        output.extend_from_slice(&arch_bytes);

        current_offset = ((current_offset + modified_data.len() + 4095) / 4096) * 4096;
    }

    // Pad to first arch offset
    while output.len() < arch_data[0].0.offset as usize {
        output.push(0);
    }

    // Write arch data
    for (arch, modified_data) in &arch_data {
        // Pad to offset
        while output.len() < arch.offset as usize {
            output.push(0);
        }
        output.extend_from_slice(modified_data);
    }

    Ok(output.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_writer_creation() {
        // This test would require actual Mach-O binary data
        // We'll add proper tests with real binaries later
    }
}
