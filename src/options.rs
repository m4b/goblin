//! Unified parsing options for binary formats
//!
//! This module provides common parsing options that can be used across
//! different binary formats (ELF, PE, Mach-O, etc.).

/// Binary parsing mode
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    /// Standard parsing mode - fails on malformed data
    Strict,
    /// Permissive parsing mode - attempts to recover from malformed data
    Permissive,
}

impl Default for ParseMode {
    fn default() -> Self {
        ParseMode::Strict
    }
}

impl ParseMode {
    /// Check if this is permissive mode
    pub fn is_permissive(&self) -> bool {
        matches!(self, ParseMode::Permissive)
    }

    /// Check if this is strict mode
    pub fn is_strict(&self) -> bool {
        matches!(self, ParseMode::Strict)
    }
}

/// Common parsing options
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    /// The parsing mode to use
    pub parse_mode: ParseMode,
}

impl Default for ParseOptions {
    fn default() -> Self {
        ParseOptions {
            parse_mode: ParseMode::Strict,
        }
    }
}

impl ParseOptions {
    /// Create new ParseOptions with default settings
    pub fn new() -> Self {
        Default::default()
    }

    /// Create ParseOptions with permissive mode enabled
    pub fn permissive() -> Self {
        ParseOptions {
            parse_mode: ParseMode::Permissive,
        }
    }

    /// Create ParseOptions with strict mode enabled
    pub fn strict() -> Self {
        ParseOptions {
            parse_mode: ParseMode::Strict,
        }
    }

    /// Set the parse mode
    pub fn with_parse_mode(mut self, parse_mode: ParseMode) -> Self {
        self.parse_mode = parse_mode;
        self
    }

    /// Check if permissive mode is enabled
    pub fn is_permissive(&self) -> bool {
        self.parse_mode.is_permissive()
    }

    /// Check if strict mode is enabled
    pub fn is_strict(&self) -> bool {
        self.parse_mode.is_strict()
    }
}
