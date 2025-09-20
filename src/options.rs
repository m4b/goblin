//! Unified parsing options for binary formats
//!
//! This module provides common parsing options that can be used across
//! different binary formats (ELF, PE, Mach-O, etc.).

/// Binary parsing mode
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
    pub(crate) fn is_permissive(&self) -> bool {
        matches!(self, ParseMode::Permissive)
    }

    /// Check if this is strict mode
    pub(crate) fn is_strict(&self) -> bool {
        matches!(self, ParseMode::Strict)
    }
}

/// Common parsing options
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
}

/// Helper trait to ease permissive parsing fallbacks.
///
/// When `permissive` is true, errors are downgraded to warnings (if `log` feature is enabled)
/// and a default or provided value is used instead; otherwise the original error is propagated.
pub(crate) trait Permissive<T, E> {
    fn or_permissive_and_default(
        self,
        permissive: bool,
        context: &str,
    ) -> core::result::Result<T, E>;

    #[allow(unused)]
    fn or_permissive_and_value(
        self,
        permissive: bool,
        context: &str,
        value: T,
    ) -> core::result::Result<T, E>;

    #[allow(unused)]
    fn or_permissive_and_then<F>(
        self,
        permissive: bool,
        context: &str,
        f: F,
    ) -> core::result::Result<T, E>
    where
        F: FnOnce() -> T;

    // no lazy-with-ctx variants; use static messages to avoid allocations
}

impl<T: Default, E: core::fmt::Display> Permissive<T, E> for core::result::Result<T, E> {
    #[allow(unused)]
    fn or_permissive_and_default(
        self,
        permissive: bool,
        context: &str,
    ) -> core::result::Result<T, E> {
        self.or_else(|e| {
            if permissive {
                #[cfg(feature = "log")]
                log::warn!("{context}: {e}, continuing with empty/default value");
                Ok(T::default())
            } else {
                Err(e)
            }
        })
    }

    #[allow(unused)]
    fn or_permissive_and_value(
        self,
        permissive: bool,
        context: &str,
        value: T,
    ) -> core::result::Result<T, E> {
        self.or_else(|e| {
            if permissive {
                #[cfg(feature = "log")]
                log::warn!("{context}: {e}, continuing with provided value");
                Ok(value)
            } else {
                Err(e)
            }
        })
    }

    // removed: *_with_ctx helpers (prefer static messages)

    #[allow(unused)]
    fn or_permissive_and_then<F>(
        self,
        permissive: bool,
        context: &str,
        f: F,
    ) -> core::result::Result<T, E>
    where
        F: FnOnce() -> T,
    {
        self.or_else(|e| {
            if permissive {
                #[cfg(feature = "log")]
                log::warn!("{context}: {e}, continuing with computed value");
                Ok(f())
            } else {
                Err(e)
            }
        })
    }

    // removed: *_with_ctx helpers (prefer static messages)

    // removed: *_with_ctx helpers (prefer static messages)
}
