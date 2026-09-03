//! Implements build attributes used by various toolchains to describe architecture-specific
//! metadata.
//!
//! This implementation was written following [ELF for the Arm Architecture] § 5.3.6, but the
//! structure is identical elsewhere.
//!
//! [ELF for the Arm Architecture]: https://developer.arm.com/documentation/ihi0044/h/?lang=en

use core::convert::TryFrom;
use core::iter::FusedIterator;
use core::str::Utf8Error;
use scroll::{Pread, Uleb128};

/// A build attributes section.
pub struct Section<'a>(&'a [u8], scroll::Endian);

impl<'a> Section<'a> {
    /// Instantiate a `Section` from the bytes of a build attributes section.
    ///
    /// `endianness` must match the ELF header, i.e. `elf::Header::endianness()`.
    pub fn new(
        section_bytes: &'a [u8],
        endianness: scroll::Endian,
    ) -> Result<Self, NewSectionError> {
        match section_bytes.get(0) {
            Some(b'A') => Ok(Section(&section_bytes[1..], endianness)),
            Some(other) => Err(NewSectionError::UnknownFormat(*other)),
            None => Err(NewSectionError::EmptySection),
        }
    }

    pub fn subsections(&self) -> SectionIter<'a> {
        SectionIter(self.0, 0, self.1)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NewSectionError {
    /// The section was empty.
    EmptySection,
    /// The section contained an unknown format, identified by this `u8`.
    UnknownFormat(u8),
}

impl<'a> IntoIterator for Section<'a> {
    type Item = Result<Subsection<'a>, SectionIterError>;
    type IntoIter = SectionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.subsections()
    }
}

impl<'a> IntoIterator for &'_ Section<'a> {
    type Item = Result<Subsection<'a>, SectionIterError>;
    type IntoIter = SectionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.subsections()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SectionIterError {
    /// The subsection at `offset` could not be parsed because the section data unexpectedly ended.
    UnexpectedEof { offset: usize },
    /// The subsection at `offset` specifies its length as `subsection_len`, while the slice is
    /// `len` bytes long.
    InvalidLength {
        offset: usize,
        len: usize,
        subsection_len: u32,
    },
    /// The subsection at `offset` is invalid and cannot be parsed.
    InvalidSubsection { offset: usize },
}

/// An iterator over a `Section`'s contents.
#[derive(Debug)]
pub struct SectionIter<'a>(&'a [u8], usize, scroll::Endian);

impl<'a> FusedIterator for SectionIter<'a> {}
impl<'a> Iterator for SectionIter<'a> {
    type Item = Result<Subsection<'a>, SectionIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.1 >= self.0.len() {
            return None;
        }

        let result = {
            // Read the length
            self.0
                .pread_with::<u32>(self.1, self.2)
                .map_err(|_| SectionIterError::UnexpectedEof { offset: self.1 })
                .and_then(|len| {
                    // Figure out and validate the end
                    self.1
                        .checked_add(len as usize)
                        .filter(|end| *end > 4)
                        .filter(|end| *end <= self.0.len())
                        .ok_or(SectionIterError::InvalidLength {
                            offset: self.1,
                            len: self.0.len(),
                            subsection_len: len,
                        })
                })
                // Get the subsection slice
                .map(|end| {
                    let start = self.1 + 4;
                    self.1 = end;
                    &self.0[start..end]
                })
                .and_then(|slice| {
                    // Map it to a Subsection
                    Subsection::new(slice, self.2)
                        .map_err(|_| SectionIterError::InvalidSubsection { offset: self.1 })
                })
        };

        if result.is_err() {
            // Break the iterator
            self.1 = self.0.len();
        }

        Some(result)
    }
}

trait SliceExt {
    fn split_at_nul(&self) -> (Self, Option<Self>)
    where
        Self: core::marker::Sized;
}

impl<'a> SliceExt for &'a [u8] {
    fn split_at_nul(&self) -> (Self, Option<Self>) {
        let mut iter = self.splitn(2, |b| *b == 0);
        (iter.next().unwrap(), iter.next())
    }
}

/// A sequence of attributes defined by a particular vendor.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Subsection<'a> {
    vendor_name: &'a [u8],
    tags: &'a [u8],
    endianness: scroll::Endian,
}

impl<'a> Subsection<'a> {
    fn new(bytes: &'a [u8], endianness: scroll::Endian) -> Result<Self, ()> {
        let (vendor_name, tags) = bytes.split_at_nul();
        tags.map(|tags| Self {
            vendor_name,
            tags,
            endianness,
        })
        .ok_or(())
    }

    /// The vendor which defined this subsection.
    pub fn vendor_name(&self) -> &[u8] {
        self.vendor_name
    }

    /// Iterate over the tags inside this subsection.
    pub fn tags(&self) -> SubsectionIter<'a> {
        SubsectionIter(self.tags, 0, self.endianness)
    }
}

impl<'a> IntoIterator for Subsection<'a> {
    type Item = Result<Group<'a>, SubsectionIterError>;
    type IntoIter = SubsectionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.tags()
    }
}

impl<'a> IntoIterator for &'_ Subsection<'a> {
    type Item = Result<Group<'a>, SubsectionIterError>;
    type IntoIter = SubsectionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.tags()
    }
}

/// An iterator over a `Subsection`'s contents.
#[derive(Debug)]
pub struct SubsectionIter<'a>(&'a [u8], usize, scroll::Endian);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum TagKind {
    File,
    Section,
    Symbol,
}
impl TryFrom<u8> for TagKind {
    type Error = SubsectionIterError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TagKind::File),
            2 => Ok(TagKind::Section),
            3 => Ok(TagKind::Symbol),
            other => Err(SubsectionIterError::UnrecognizedKind(other)),
        }
    }
}

impl<'a> FusedIterator for SubsectionIter<'a> {}
impl<'a> Iterator for SubsectionIter<'a> {
    type Item = Result<Group<'a>, SubsectionIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = match self.0.get(self.1).map(|num| TagKind::try_from(*num)) {
            Some(Ok(kind)) => {
                // Read the size following the tag
                self.0
                    .pread_with::<u32>(self.1 + 1, self.2)
                    .map_err(SubsectionIterError::SizeParseError)
                    .and_then(|size| {
                        // Convert the size to a u64
                        usize::try_from(size)
                            // Drop the existing error
                            .ok()
                            // Ensure it's at least the 1 byte (tag) + 4 bytes (size) already read
                            .filter(|end| *end >= 5)
                            // Add it to the start of the tag
                            .and_then(|size| size.checked_add(self.1))
                            // Ensure it's within the slice bounds
                            .filter(|end| *end <= self.0.len())
                            // Turn failures into an error
                            .ok_or(SubsectionIterError::SizeTooBig {
                                offset: self.1,
                                length: self.0.len(),
                                tag_size: size,
                            })
                    })
                    .map(|end| {
                        // Success!
                        // Make the slice
                        let start = self.1 + 5;
                        let slice = &self.0[start..end];
                        // Update the cursor
                        self.1 = end;
                        // Make the Tag
                        match kind {
                            TagKind::File => Group::File(FileGroup(slice)),
                            TagKind::Section => Group::Section(SectionGroup(slice)),
                            TagKind::Symbol => Group::Symbol(SymbolGroup(slice)),
                        }
                    })
            }
            Some(Err(err)) => Err(err),
            None => return None,
        };

        if result.is_err() {
            // Kill the iterator
            self.1 = self.0.len();
        }

        Some(result)
    }
}

#[derive(Debug)]
pub enum SubsectionIterError {
    UnrecognizedKind(u8),
    SizeParseError(scroll::Error),
    SizeTooBig {
        offset: usize,
        length: usize,
        tag_size: u32,
    },
}

/// A group of attributes, applying to all or a part of this executable file.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Group<'a> {
    /// A group of attributes applying to the entire file.
    File(FileGroup<'a>),
    /// A group of attributes applying to specific ELF sections.
    Section(SectionGroup<'a>),
    /// A group of attributes applying to specific symbols.
    Symbol(SymbolGroup<'a>),
}

/// A group of attributes applying to the entire file.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FileGroup<'a>(&'a [u8]);

impl<'a> FileGroup<'a> {
    pub fn attributes(&self) -> Attributes<'a> {
        Attributes(self.0)
    }
}

/// A group of attributes applying to specific ELF sections.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SectionGroup<'a>(&'a [u8]);

impl<'a> SectionGroup<'a> {
    /// Iterate over the group, returning the sections to which this group applies followed by the
    /// attributes themselves.
    pub fn iter(&self) -> SectionGroupIter<'a> {
        SectionGroupIter(self.0, 0)
    }

    /// Return the section numbers for this group, discarding errors and discarding attributes.
    pub fn section_numbers(&self) -> impl Iterator<Item = u64> + 'a {
        self.iter().filter_map(|i| match i {
            Ok(SectionGroupItem::SectionNumber(n)) => Some(n),
            _ => None,
        })
    }

    /// Return the attributes for this group, discarding errors and discarding section numbers.
    pub fn attributes(&self) -> Option<Attributes<'a>> {
        self.iter()
            .filter_map(|i| match i {
                Ok(SectionGroupItem::Attributes(a)) => Some(a),
                _ => None,
            })
            .next()
    }
}

impl<'a> IntoIterator for SectionGroup<'a> {
    type Item = Result<SectionGroupItem<'a>, GroupIterError>;
    type IntoIter = SectionGroupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<'a> IntoIterator for &'_ SectionGroup<'a> {
    type Item = Result<SectionGroupItem<'a>, GroupIterError>;
    type IntoIter = SectionGroupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug)]
pub enum GroupIterError {
    InvalidNumber(scroll::Error),
}

/// An iterator over a `SectionGroup`'s contents.
pub struct SectionGroupIter<'a>(&'a [u8], usize);

impl<'a> FusedIterator for SectionGroupIter<'a> {}
impl<'a> Iterator for SectionGroupIter<'a> {
    type Item = Result<SectionGroupItem<'a>, GroupIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.1 >= self.0.len() {
            return None;
        }

        Some(
            Uleb128::read(self.0, &mut self.1)
                .map(|value| {
                    if value == 0 {
                        // This is the terminator
                        // Get the rest of the bytes
                        let rest = &self.0[self.1..];
                        // Break the iterator
                        self.1 = self.0.len();
                        // Return it as attributes
                        SectionGroupItem::Attributes(Attributes(rest))
                    } else {
                        // Normal value
                        SectionGroupItem::SectionNumber(value)
                    }
                })
                .map_err(|e| {
                    // Break the iterator
                    self.1 = self.0.len();
                    // Return the error
                    GroupIterError::InvalidNumber(e)
                }),
        )
    }
}

/// An item contained by a `SectionGroup`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SectionGroupItem<'a> {
    /// A section number to which this `SectionGroup` applies.
    SectionNumber(u64),
    /// The set of attributes which applies to these sections.
    Attributes(Attributes<'a>),
}

/// A group of attributes applying to specific symbols.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SymbolGroup<'a>(&'a [u8]);

impl<'a> SymbolGroup<'a> {
    /// Iterate over the group, returning the symbols to which this group applies followed by the
    /// attributes themselves.
    pub fn iter(&self) -> SymbolGroupIter<'a> {
        SymbolGroupIter(SectionGroupIter(self.0, 0))
    }

    /// Return the symbol numbers for this group, discarding errors and discarding attributes.
    pub fn section_numbers(&self) -> impl Iterator<Item = u64> + 'a {
        self.iter().filter_map(|i| match i {
            Ok(SymbolGroupItem::SymbolNumber(n)) => Some(n),
            _ => None,
        })
    }

    /// Return the attributes for this group, discarding errors and discarding symbol numbers.
    pub fn attributes(&self) -> Option<Attributes<'a>> {
        self.iter()
            .filter_map(|i| match i {
                Ok(SymbolGroupItem::Attributes(a)) => Some(a),
                _ => None,
            })
            .next()
    }
}

impl<'a> IntoIterator for SymbolGroup<'a> {
    type Item = Result<SymbolGroupItem<'a>, GroupIterError>;
    type IntoIter = SymbolGroupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<'a> IntoIterator for &'_ SymbolGroup<'a> {
    type Item = Result<SymbolGroupItem<'a>, GroupIterError>;
    type IntoIter = SymbolGroupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over a `SymbolGroup`'s contents.
pub struct SymbolGroupIter<'a>(
    // Symbol groups are equivalent to section groups except what we call the enum discriminant
    // Implement it as such
    SectionGroupIter<'a>,
);

impl<'a> FusedIterator for SymbolGroupIter<'a> {}
impl<'a> Iterator for SymbolGroupIter<'a> {
    type Item = Result<SymbolGroupItem<'a>, GroupIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.next() {
            Some(Ok(SectionGroupItem::SectionNumber(n))) => {
                Some(Ok(SymbolGroupItem::SymbolNumber(n)))
            }
            Some(Ok(SectionGroupItem::Attributes(a))) => Some(Ok(SymbolGroupItem::Attributes(a))),
            Some(Err(e)) => Some(Err(e)),
            None => None,
        }
    }
}

/// An item contained by a `SymbolGroup`.
pub enum SymbolGroupItem<'a> {
    /// A symbol number to which this `SymbolGroup` applies.
    SymbolNumber(u64),
    /// The set of attributes which applies to these symbols.
    Attributes(Attributes<'a>),
}

/// An unparsed set of attributes.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Attributes<'a>(&'a [u8]);

impl<'a> Attributes<'a> {
    /// Consume `Attributes`, returning an `UnparsedAttribute` .
    pub(crate) fn next(self) -> Option<Result<SemiParsedAttribute<'a>, AttributeParseError>> {
        if self.0.is_empty() {
            None
        } else {
            let mut offset = 0;
            Some(
                Uleb128::read(self.0, &mut offset)
                    .map_err(AttributeParseError::TagParseError)
                    .map(|tag_number| SemiParsedAttribute(tag_number, &self.0[offset..])),
            )
        }
    }
}

/// A tag number, followed by its unparsed payload and subsequent attributes.
pub(crate) struct SemiParsedAttribute<'a>(u64, &'a [u8]);

impl<'a> SemiParsedAttribute<'a> {
    pub fn tag_number(&self) -> u64 {
        self.0
    }

    /// Return an error indicating this tag is unrecognized.
    pub(crate) fn unrecognized(&self) -> AttributeParseError {
        AttributeParseError::UnknownTag(self.0)
    }

    /// Parse a NUL-terminated byte string, returning subsequent attributes.
    pub(crate) fn parse_ntbs(&self) -> Result<(&'a [u8], Attributes<'a>), AttributeParseError> {
        let (str, rest) = self.1.split_at_nul();
        rest.map(|rest| (str, Attributes(rest)))
            .ok_or(AttributeParseError::MissingNulTerminator(self.0))
    }

    /// Parse a ULEB 128, returning subsequent attributes.
    pub(crate) fn parse_uleb128(&self) -> Result<(u64, Attributes<'a>), AttributeParseError> {
        let mut offset = 0;
        Uleb128::read(self.1, &mut offset)
            .map(|value| (value, Attributes(&self.1[offset..])))
            .map_err(|_| AttributeParseError::InvalidUleb128(self.0))
    }

    /// Parse a ULEB 128 followed by a NUL-terminated byte string, returning subsequent attributes.
    pub(crate) fn parse_uleb128_ntbs(
        &self,
    ) -> Result<(u64, &'a [u8], Attributes<'a>), AttributeParseError> {
        // Read the ULEB128
        let mut offset = 0;
        let flag = Uleb128::read(self.1, &mut offset)
            .map_err(|_| AttributeParseError::InvalidUleb128(self.0))?;

        // Read the NTBS
        let rest = &self.1[offset..];
        let (str, rest) = rest.split_at_nul();
        rest.map(|rest| (flag, str, Attributes(rest)))
            .ok_or(AttributeParseError::MissingNulTerminator(self.0))
    }
}

#[derive(Debug)]
pub enum AttributeParseError {
    /// The attribute tag could not be parsed
    TagParseError(scroll::Error),
    /// The attribute tag was not recognized
    UnknownTag(u64),
    /// The attribute with this tag number is NUL-terminated but does not have a NUL terminator.
    MissingNulTerminator(u64),
    /// The attribute with this tag number contains an invalid ULEB-128 encoded parameter.
    InvalidUleb128(u64),
}

/// An opaque unknown value.
///
/// Tag enumerations are all `#[non_exhaustive]`, and they all have an `Unknown(UnknownValue)`
/// variant to allow the tag enumeration to contain every value even if it cannot articulate every
/// value. The `UnknownValue` type is opaque to discourage matching on this `Unknown` variant.
///
/// Instead of explicitly matching `Unknown`, use the fall-through forced by `#[non_exhaustive]` to
/// match all values not recognized by your application together:
///
/// ```
/// # use goblin::elf::build_attributes::aeabi::*;
/// # let abi_fp_rounding = AbiFpRounding::from(123);
/// match abi_fp_rounding {
///     AbiFpRounding::ChosenAtRuntime => {
///         /* case A */
///     },
///     AbiFpRounding::RoundToNearest => {
///         /* case B */
///     },
///     other => {
///         /* case forced by #[non_exhaustive] */
///         /* if you must discriminate further, use `u64::from(other)` to access the raw value */
///     },
/// }
/// ```
///
/// This pattern allows future versions of `goblin` to add variants to existing enumerations without
/// breaking source compatibility. If e.g. `AbiFpRounding::RoundToZero = 2` was defined in a
/// subsequent revision, it would be fall into `other` and be handled by your application the same
/// way, even as a `goblin` update changes its modeling from `AbiFpRounding::Unknown(2)` to
/// `AbiFpRounding::RoundToZero`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UnknownValue(pub(crate) u64);

/// An error which occurred while parsing some kind of build attributes data structure.
#[derive(Debug)]
pub enum Error {
    /// The entire build attributes section was invalid.
    InvalidSection(NewSectionError),
    /// The requested vendor subsection was not found.
    VendorNotFound,
    /// An error occurred while iterating over a `Section`.
    Section(SectionIterError),
    /// An error occurred while iterating over a `Subsection`.
    Subsection(SubsectionIterError),
    /// An error occurred while parsing `Attributes`.
    Attributes(AttributeParseError),
}

impl From<NewSectionError> for Error {
    fn from(e: NewSectionError) -> Self {
        Self::InvalidSection(e)
    }
}
impl From<SectionIterError> for Error {
    fn from(e: SectionIterError) -> Self {
        Self::Section(e)
    }
}
impl From<SubsectionIterError> for Error {
    fn from(e: SubsectionIterError) -> Self {
        Self::Subsection(e)
    }
}
impl From<AttributeParseError> for Error {
    fn from(e: AttributeParseError) -> Self {
        Self::Attributes(e)
    }
}

macro_rules! build_attributes {
    (
    $(#[$outer_meta:meta])*
    $t:ident {
        vendor_name: $vendor_name:literal
        unknown_tag: $unknown_tag_var:ident => { $unknown_tag_expr:expr }
        $(
            $(#[$field_meta:meta])*
            [$n:ident, (= $tag:literal), $(#[$typ_meta:meta])* $typ:tt $($rest:tt)*]
        )+
    }) => {
        // Define all the types
        $(
        build_attributes!(@define_type(
            $(#[$typ_meta])* $typ $($rest)*
        ));
        )+

        // Define the main struct
        $(#[$outer_meta])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
        #[non_exhaustive]
        pub struct $t<'a> {
            // Define all the fields
            $(
            $(#[$field_meta])*
            pub $n: Option<build_attributes!(@field_type($typ $($rest)*))>,
            )+
        }

        #[allow(deprecated)]
        impl<'a> $t<'a> {
            fn new() -> Self {
                Self {
                    $($n: Default::default(),)+
                }
            }

            /// Parse `Attributes`, merging it into this object.
            fn parse(&mut self, mut attrs: Attributes<'a>) -> Result<(), AttributeParseError> {
                while let Some(attr) = attrs.next() {
                    let attr = attr?;
                    match attr.tag_number() {
                        $(
                        $tag => {
                            let (value, rest) = $typ::parse(attr)?;
                            self.$n = Some(value);
                            attrs = rest;
                        },
                        )+
                        _ => {
                            // unknown tag
                            let $unknown_tag_var = attr;
                            attrs = $unknown_tag_expr;
                        },
                    }
                }
                Ok(())
            }

            /// The byte string which identifies this vendor section.
            pub const VENDOR_NAME: &'static [u8] = $vendor_name;
        }

        impl<'a> core::convert::TryFrom<Attributes<'a>> for $t<'a> {
            type Error = AttributeParseError;

            fn try_from(attrs: Attributes<'a>) -> Result<Self, Self::Error> {
                let mut vendor = Self::new();
                vendor.parse(attrs)?;
                Ok(vendor)
            }
        }

        impl<'a> core::convert::TryFrom<Section<'a>> for $t<'a> {
            type Error = Error;

            fn try_from(section: Section<'a>) -> Result<Self, Self::Error> {
                for subsection in section {
                    let subsection = subsection?;
                    if subsection.vendor_name() != $t::VENDOR_NAME {
                        continue;
                    }
                    for group in subsection {
                        match group? {
                            Group::File(g) => {
                                return $t::try_from(g.attributes()).map_err(|e| e.into())
                            }
                            _ => {},
                        }
                    }
                }
                Err(Error::VendorNotFound)
            }
        }

        impl<'a> core::ops::Add<Attributes<'a>> for $t<'a> {
            type Output = Result<Self, AttributeParseError>;

            fn add(self, attrs: Attributes<'a>) -> Self::Output {
                let mut vendor = self.clone();
                vendor.parse(attrs)?;
                Ok(vendor)
            }
        }
    };

    (@field_type($t:tt(NTBS) )) => { $t<'a> };
    (@field_type($t:tt(Uleb128, NTBS) )) => { $t<'a> };
    (@field_type($t:tt { $($rest:tt)* } )) => { $t };

    (@define_type($(#[$typ_meta:meta])* $t:tt(NTBS) )) => {
        $(#[$typ_meta:meta])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $t<'a>(&'a [u8]);

        impl<'a> $t<'a> {
            fn parse(attr: SemiParsedAttribute<'a>) -> Result<(Self, Attributes<'a>), AttributeParseError> {
                let (value, rest) = attr.parse_ntbs()?;
                Ok((Self(value), rest))
            }

            /// Return the value as a `&[u8]`.
            pub fn as_bytes(&self) -> &'a [u8] {
                self.0
            }

            /// Return the value as a `&str`, provided it is encoded as UTF-8.
            pub fn as_str(&self) -> Result<&'a str, Utf8Error> {
                core::str::from_utf8(self.0)
            }

            /// Return the value as a `Cow<str>`, discarding invalid UTF-8.
            #[cfg(feature = "std")]
            pub fn to_string_lossy(&self) -> std::borrow::Cow<'a, str> {
                String::from_utf8_lossy(self.0)
            }
        }

        impl<'a> AsRef<[u8]> for $t<'a> {
            fn as_ref(&self) -> &[u8] {
                self.0
            }
        }

        impl<'a> From<&'a [u8]> for $t<'a> {
            fn from(bytes: &'a [u8]) -> Self {
                Self(bytes)
            }
        }

        impl<'a> From<$t<'a>> for &'a [u8] {
            fn from(v: $t<'a>) -> Self {
                v.0
            }
        }
    };
    (@define_type($(#[$typ_meta:meta])* $t:tt(Uleb128, NTBS) )) => {
        $(#[$typ_meta:meta])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $t<'a>(u64, &'a [u8]);

        impl<'a> $t<'a> {
            fn parse(attr: SemiParsedAttribute<'a>) -> Result<(Self, Attributes<'a>), AttributeParseError> {
                let (flag, str, rest) = attr.parse_uleb128_ntbs()?;
                Ok((Self(flag, str), rest))
            }

            /// Return the flag value.
            pub fn flag(&self) -> u64 {
                self.0
            }

            /// Return the string value as a `&[u8]`.
            pub fn as_bytes(&self) -> &'a [u8] {
                self.1
            }

            /// Return the string value as a `&str`, provided it is encoded as UTF-8.
            pub fn as_str(&self) -> Result<&'a str, Utf8Error> {
                core::str::from_utf8(self.1)
            }

            /// Return the string value as a `Cow<str>`, discarding invalid UTF-8.
            #[cfg(feature = "std")]
            pub fn to_string_lossy(&self) -> std::borrow::Cow<'a, str> {
                String::from_utf8_lossy(self.1)
            }
        }

        impl<'a> AsRef<[u8]> for $t<'a> {
            fn as_ref(&self) -> &[u8] {
                self.1
            }
        }

        impl<'a> From<(u64, &'a [u8])> for $t<'a> {
            fn from(tup: (u64, &'a [u8])) -> Self {
                Self(tup.0, tup.1)
            }
        }

        impl<'a> From<$t<'a>> for (u64, &'a [u8]) {
            fn from(v: $t<'a>) -> Self {
                (v.0, v.1)
            }
        }
    };
    (@define_type($(#[$typ_meta:meta])* $t:tt {
        $(
        $(#[$variant_meta:meta])*
        $value:literal => $variant:tt,
        )+
    })) => {
        $(#[$typ_meta:meta])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        #[non_exhaustive]
        pub enum $t {
            $(
            $(#[$variant_meta])*
            $variant,
            )+
            /// A numeric value with unknown meaning.
            ///
            /// Avoid matching `Unknown`. See [`UnknownValue`] for details.
            ///
            /// [`UnknownValue`]: ../struct.UnknownValue.html
            #[deprecated(note = "Avoid matching Unknown; this enum is non-exhaustive")]
            Unknown(UnknownValue),
        }

        impl $t {
            fn parse<'a>(attr: SemiParsedAttribute<'a>) -> Result<(Self, Attributes<'a>), AttributeParseError> {
                let (value, rest) = attr.parse_uleb128()?;
                Ok((Self::from(value), rest))
            }
        }

        impl Default for $t {
            fn default() -> Self {
                Self::from(0u64)
            }
        }

        impl From<u64> for $t {
            #[allow(deprecated)]
            fn from(value: u64) -> Self {
                match value {
                    $($value => $t::$variant,)+
                    other => $t::Unknown(UnknownValue(other)),
                }
            }
        }

        impl From<$t> for u64 {
            #[allow(deprecated)]
            fn from(value: $t) -> u64 {
                match value {
                    $($t::$variant => $value,)+
                    $t::Unknown(UnknownValue(value)) => value,
                }
            }
        }

        impl From<&'_ $t> for u64 {
            fn from(value: &'_ $t) -> u64 {
                u64::from(*value)
            }
        }
    };
}

pub mod aeabi;
