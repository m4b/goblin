// Reference:
//   https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode
//   https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx

// Authenticode works by omiting sections of the PE binary from the digest
// those sections are:
//   - checksum
//   - data directory entry for certtable
//   - certtable

use alloc::{boxed::Box, vec::Vec};
use core::ops::Range;
use digest::{Digest, Output};

use super::PE;

impl PE<'_> {
    /// [`authenticode_ranges`] returns the various ranges of the binary that are relevant for
    /// signature.
    fn authenticode_ranges(&self) -> ExcludedAuthenticodeSectionsIter<'_> {
        ExcludedAuthenticodeSectionsIter {
            pe: self,
            state: IterState::default(),
        }
    }

    /// [`authenticode_digest`] returns the result of the provided hash algorithm.
    pub fn authenticode_digest<D: Digest>(&self) -> Output<D> {
        let mut digest = D::new();

        for chunk in self.authenticode_ranges() {
            digest.update(chunk);
        }

        digest.finalize()
    }

    /// [`authenticode_slice`] is intended for convenience when signing a binary with a PKCS#11
    /// interface (HSM interface).
    /// Some algorithms (RSA-PKCS at least) for signature require the non-prehashed slice to be provided.
    pub fn authenticode_slice(&self) -> Box<[u8]> {
        // PE may be 70-80MB large (especially for linux UKIs). We'll get the length beforehand as
        // it's cheaper than getting Vec to realloc and move stuff around multiple times.
        let mut length = 0;
        for chunk in self.authenticode_ranges() {
            length += chunk.len();
        }

        let mut out = Vec::with_capacity(length);
        for chunk in self.authenticode_ranges() {
            out.extend_from_slice(chunk);
        }

        out.into()
    }
}

/// [`ExcludedAuthenticodeSections`] holds the various ranges of the binary that are expected to be
/// excluded from the authenticode computation.
#[derive(Debug, Clone, Default)]
pub(super) struct ExcludedAuthenticodeSections {
    pub checksum: Range<usize>,
    pub datadir_entry_certtable: Range<usize>,
    pub certtable: Option<Range<usize>>,
}

pub struct ExcludedAuthenticodeSectionsIter<'s> {
    pe: &'s PE<'s>,
    state: IterState,
}

#[derive(Default, Debug, PartialEq)]
enum IterState {
    #[default]
    Initial,
    DatadirEntry(usize),
    CertTable(usize),
    Final(usize),
    Done,
}

impl<'s> Iterator for ExcludedAuthenticodeSectionsIter<'s> {
    type Item = &'s [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = &self.pe.bytes;

        if let Some(sections) = self.pe.excluded_authenticode_sections.as_ref() {
            loop {
                match self.state {
                    IterState::Initial => {
                        self.state = IterState::DatadirEntry(sections.checksum.end);
                        return Some(&bytes[..sections.checksum.start]);
                    }
                    IterState::DatadirEntry(start) => {
                        self.state = IterState::CertTable(sections.datadir_entry_certtable.end);
                        return Some(&bytes[start..sections.datadir_entry_certtable.start]);
                    }
                    IterState::CertTable(start) => {
                        if let Some(certtable) = sections.certtable.as_ref() {
                            self.state = IterState::Final(certtable.end);
                            return Some(&bytes[start..certtable.start]);
                        } else {
                            self.state = IterState::Final(start)
                        }
                    }
                    IterState::Final(start) => {
                        self.state = IterState::Done;
                        return Some(&bytes[start..]);
                    }
                    IterState::Done => return None,
                }
            }
        } else {
            loop {
                match self.state {
                    IterState::Initial => {
                        self.state = IterState::Done;
                        return Some(bytes);
                    }
                    IterState::Done => return None,
                    _ => {
                        self.state = IterState::Done;
                    }
                }
            }
        }
    }
}
