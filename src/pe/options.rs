pub use crate::options::ParseMode;

/// Parsing Options structure for the PE parser
#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
pub struct ParseOptions {
    /// Wether the parser should resolve rvas or not. Default: true
    pub resolve_rva: bool,
    /// Whether or not to parse attribute certificates.
    /// Set to false for in-memory representation, as the [loader does not map this info into
    /// memory](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#other-contents-of-the-file).
    /// For on-disk representations, leave as true. Default: true
    pub parse_attribute_certificates: bool,
    /// Whether or not to parse tls data. Default: true
    pub parse_tls_data: bool,
    /// Whether or not to parse resources. Default: true
    pub parse_resources: bool,
    /// Whether or not to end with an error in case of incorrect data or continue parsing if able. Default: ParseMode::Strict
    pub parse_mode: ParseMode,
    /// Whether or not to parse import tables. Set to false if you only need headers,
    /// debug info, or exports. This can dramatically speed up parsing for PE files with
    /// large or malformed import tables. Default: true
    pub parse_imports: bool,
}

impl Default for ParseOptions {
    /// Returns a parse options structure with default values
    fn default() -> Self {
        ParseOptions {
            resolve_rva: true,
            parse_attribute_certificates: true,
            parse_tls_data: true,
            parse_resources: true,
            parse_mode: ParseMode::Strict,
            parse_imports: true,
        }
    }
}

impl ParseOptions {
    #[cfg(feature = "te")]
    pub(crate) fn te() -> Self {
        Self {
            resolve_rva: false,
            parse_attribute_certificates: false,
            parse_tls_data: true,
            parse_resources: true,
            parse_mode: ParseMode::Strict,
            parse_imports: true,
        }
    }

    pub fn with_parse_mode(mut self, parse_mode: ParseMode) -> Self {
        self.parse_mode = parse_mode;
        self
    }

    pub fn with_parse_tls_data(mut self, parse_tls_data: bool) -> Self {
        self.parse_tls_data = parse_tls_data;
        self
    }

    pub fn with_parse_resources(mut self, parse_resources: bool) -> Self {
        self.parse_resources = parse_resources;
        self
    }

    pub fn with_parse_imports(mut self, parse_imports: bool) -> Self {
        self.parse_imports = parse_imports;
        self
    }
}
