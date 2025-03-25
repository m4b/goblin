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
    /// Whether or not to end with an error in case of incorrect data or continue parsing if able. Default: ParseMode::Strict
    pub parse_mode: ParseMode,
}

#[derive(Debug, Copy, Clone)]
pub enum ParseMode {
    /// Always end with error on incorrect data
    Strict,
    /// Incorrect data will not cause to end with error if possible
    Permissive,
}

impl Default for ParseOptions {
    /// Returns a parse options structure with default values
    fn default() -> Self {
        ParseOptions {
            resolve_rva: true,
            parse_attribute_certificates: true,
            parse_mode: ParseMode::Strict,
        }
    }
}

impl ParseOptions {
    pub(crate) fn te() -> Self {
        Self {
            resolve_rva: false,
            parse_attribute_certificates: false,
            parse_mode: ParseMode::Strict,
        }
    }
}
