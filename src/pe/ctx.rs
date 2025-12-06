use crate::{
    container::Container,
    pe::{options, section_table},
};

/// A binary parsing context for PE parser
#[derive(Debug, Copy, Clone)]
pub(crate) struct PeCtx<'a> {
    pub(crate) container: Container,
    pub(crate) le: scroll::Endian,
    pub(crate) sections: &'a [section_table::SectionTable],
    pub(crate) file_alignment: u32,
    pub(crate) opts: options::ParseOptions,
    pub(crate) bytes: &'a [u8], // full binary view
}

impl<'a> PeCtx<'a> {
    /// Make a new instance of [PeCtx]
    pub(crate) fn new(
        container: Container,
        le: scroll::Endian,
        sections: &'a [section_table::SectionTable],
        file_alignment: u32,
        opts: options::ParseOptions,
        bytes: &'a [u8],
    ) -> Self {
        Self {
            container,
            le,
            sections,
            file_alignment,
            opts,
            bytes,
        }
    }

    /// Whether this binary container context is "big" or not
    pub(crate) fn is_big(self) -> bool {
        self.container.is_big()
    }

    /// Whether this binary container context is little endian or not
    pub(crate) fn is_little_endian(self) -> bool {
        self.le.is_little()
    }

    /// Return a dubious pointer/address byte size for the container
    pub(crate) fn size(self) -> usize {
        match self.container {
            // TODO: require pointer size initialization/setting or default to container size with these values, e.g., avr pointer width will be smaller iirc
            Container::Little => 4,
            Container::Big => 8,
        }
    }
}
