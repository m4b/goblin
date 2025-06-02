//! ELF parsing options and modes

/// ELF parsing mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    /// Standard parsing mode - fails on malformed data
    Normal,
    /// Permissive parsing mode - attempts to recover from malformed data
    Permissive,
}

impl Default for ParseMode {
    fn default() -> Self {
        ParseMode::Normal
    }
}

/// ELF parsing options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    /// The parsing mode to use
    pub parse_mode: ParseMode,
}

impl Default for ParseOptions {
    fn default() -> Self {
        ParseOptions {
            parse_mode: ParseMode::Normal,
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

    /// Check if permissive mode is enabled
    pub fn is_permissive(&self) -> bool {
        self.parse_mode == ParseMode::Permissive
    }
}
