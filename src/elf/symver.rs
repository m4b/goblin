//! Symbol versioning
//!
//! Implementation of the GNU symbol versioning extension according to
//! [LSB Core Specification - Symbol Versioning][lsb-symver].
//!
//! List the dependencies of an ELF file that have version needed information along with the
//! versions needed for each dependency.
//! ```rust
//! use goblin::error::Error;
//!
//! pub fn show_verneed(bytes: &[u8]) -> Result<(), Error> {
//!     let binary = goblin::elf::Elf::parse(&bytes)?;
//!
//!     if let Some(verneed) = binary.verneed {
//!         for need_file in verneed.iter() {
//!             println!(
//!                 "Depend on {:?} with version(s):",
//!                 verneed.symstr.get_at(need_file.vn_file as usize)
//!             );
//!             for need_ver in need_file.iter() {
//!                 println!("{:?}", verneed.symstr.get_at(need_ver.vna_name as usize));
//!             }
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! [lsb-symver]: https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html

macro_rules! if_cfg_elf {
    ($($i:item)*) => ($(
        #[cfg(all(any(feature = "elf32", feature = "elf64"), feature = "alloc"))]
        $i
    )*)
}

if_cfg_elf! {

use crate::container;
use crate::strtab::Strtab;
use crate::elf::section_header::{SectionHeader, SHT_GNU_VERNEED};
use crate::error::{Error, Result};
use scroll::Pread;

/// An ELF `Version Need` entry Elfxx_Verneed.
///
/// https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html#VERNEEDFIG
#[repr(C)]
#[derive(Debug, Pread)]
struct ElfVerneed {
    /// Version of structure. This value is currently set to 1, and will be reset if the versioning
    /// implementation is incompatibly altered.
    vn_version: u16,
    /// Number of associated verneed array entries.
    vn_cnt: u16,
    /// Offset to the file name string in the section header, in bytes.
    vn_file: u32,
    /// Offset to a corresponding entry in the vernaux array, in bytes.
    vn_aux: u32,
    /// Offset to the next verneed entry, in bytes.
    vn_next: u32,
}

/// An ELF `Version Need Auxiliary` entry Elfxx_Vernaux.
///
/// https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html#VERNEEDEXTFIG
#[repr(C)]
#[derive(Debug, Pread)]
struct ElfVernaux {
    /// Dependency name hash value (ELF hash function).
    vna_hash: u32,
    /// Dependency information flag bitmask.
    vna_flags: u16,
    /// Object file version identifier used in the .gnu.version symbol version array. Bit number 15
    /// controls whether or not the object is hidden; if this bit is set, the object cannot be used
    /// and the static linker will ignore the symbol's presence in the object.
    vna_other: u16,
    /// Offset to the dependency name string in the section header, in bytes.
    vna_name: u32,
    /// Offset to the next vernaux entry, in bytes.
    vna_next: u32,
}

/// Helper struct to iterate over [`Version Needed`][Verneed] and [`Version Needed
/// Auxiliary`][Vernaux] entries.
#[derive(Debug)]
pub struct VerneedSection<'a> {
    /// String table used to resolve version strings.
    pub symstr: Strtab<'a>,
    bytes: &'a [u8],
    count: usize,
    ctx: container::Ctx,
}

impl<'a> VerneedSection<'a> {
    /// Try to parse the optional [`SHT_GNU_VERNEED`] section.
    pub fn parse(
        bytes: &'a [u8],
        shdrs: &'_ [SectionHeader],
        ctx: container::Ctx,
    ) -> Result<Option<VerneedSection<'a>>> {
        // Get fields needed from optional `version needed` section.
        let (link_idx, offset, size, count) =
            if let Some(shdr) = shdrs.iter().find(|shdr| shdr.sh_type == SHT_GNU_VERNEED) {
                (
                    shdr.sh_link as usize, // Encodes the string table.
                    shdr.sh_offset as usize,
                    shdr.sh_size as usize,
                    shdr.sh_info as usize, // Encodes the number of ElfVerneed entries.
                )
            } else {
                return Ok(None);
            };

        // Get string table which is used to resolve version strings.
        let symstr = {
            // Linked section refers to string table.
            let shdr_link = shdrs.get(link_idx).ok_or(Error::Malformed(
                "Section header of string table for SHT_GNU_VERNEED section not found!".into(),
            ))?;

            Strtab::parse(
                bytes,
                shdr_link.sh_offset as usize,
                shdr_link.sh_size as usize,
                0x0, /* Delimiter */
            )?
        };

        // Get a slice of bytes of the `version needed` section content.
        let bytes: &'a [u8] = bytes.pread_with(offset, size)?;

        Ok(Some(VerneedSection {
            symstr,
            bytes,
            count,
            ctx,
        }))
    }

    /// Get an iterator over the [`Verneed`] entries.
    pub fn iter(&'a self) -> VerneedIterator<'a> {
        VerneedIterator {
            bytes: self.bytes,
            count: self.count,
            index: 0,
            offset: 0,
            ctx: self.ctx,
        }
    }
}

/// Iterator over the [`Verneed`] entries from the [`SHT_GNU_VERNEED`] section.
pub struct VerneedIterator<'a> {
    bytes: &'a [u8],
    count: usize,
    index: usize,
    offset: usize,
    ctx: container::Ctx,
}

impl<'a> Iterator for VerneedIterator<'a> {
    type Item = Verneed<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            None
        } else {
            self.index += 1;
            // Safe to unwrap as the length of the byte slice was validated in VerneedSection::parse.
            let ElfVerneed {
                vn_version,
                vn_cnt,
                vn_file,
                vn_aux,
                vn_next,
            } = self.bytes.pread_with(self.offset, self.ctx.le).unwrap();

            // Get a slice of bytes of the `Vernaux` entries.
            //
            // | Verneed | .. | Verneed | Vernaux | Vernaux | .. | Verneed | ..
            // ^--------------^
            //  offset        ^---------^
            //                 vn_aux
            //                ^----------------------------------^
            //                 vn_next
            //
            // Safe to unwrap as the length of the byte slice was validated in VerneedSection::parse.
            let len = if vn_next > 0 {
                (vn_next - vn_aux) as usize
            } else {
                // For the last entry, ElfVerneed->vn_next == 0.
                // Therefore we compute the remaining length of bytes buffer.
                self.bytes.len() - self.offset - vn_aux as usize
            };
            let bytes: &'a [u8] = self
                .bytes
                .pread_with(self.offset + vn_aux as usize, len)
                .unwrap();

            // Bump the offset to the next ElfVerneed entry.
            self.offset += vn_next as usize;

            Some(Verneed {
                vn_version,
                vn_cnt,
                vn_file,
                vn_aux,
                vn_next,
                bytes,
                ctx: self.ctx,
            })
        }
    }
}

/// An ELF [`Version Need`][lsb-verneed] entry .
///
/// [lsb-verneed]: https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html#VERNEEDFIG
#[derive(Debug)]
pub struct Verneed<'a> {
    pub vn_version: u16,
    pub vn_cnt: u16,
    pub vn_file: u32,
    pub vn_aux: u32,
    pub vn_next: u32,

    bytes: &'a [u8],
    ctx: container::Ctx,
}

impl<'a> Verneed<'a> {
    /// Get an iterator over the [`Vernaux`] entries of this [`Verneed`] entry.
    pub fn iter(&'a self) -> VernauxIterator<'a> {
        VernauxIterator {
            bytes: self.bytes,
            count: self.vn_cnt as usize,
            index: 0,
            offset: 0,
            ctx: self.ctx,
        }
    }
}

/// Iterator over the [`Vernaux`] entries for an specific [`Verneed`] entry.
pub struct VernauxIterator<'a> {
    bytes: &'a [u8],
    count: usize,
    index: usize,
    offset: usize,
    ctx: container::Ctx,
}

impl<'a> Iterator for VernauxIterator<'a> {
    type Item = Vernaux;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            None
        } else {
            self.index += 1;

            // Safe to unwrap as the length of the byte slice was validated in VerneedIterator::next.
            let ElfVernaux {
                vna_hash,
                vna_flags,
                vna_other,
                vna_name,
                vna_next,
            } = self.bytes.pread_with(self.offset, self.ctx.le).unwrap();

            // Bump the offset to the next ElfVernaux entry.
            self.offset += vna_next as usize;

            Some(Vernaux {
                vna_hash,
                vna_flags,
                vna_other,
                vna_name,
                vna_next,
            })
        }
    }
}

/// An ELF [`Version Need Auxiliary`][lsb-vernaux] entry.
///
/// [lsb-vernaux]: https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html#VERNEEDEXTFIG
#[derive(Debug)]
pub struct Vernaux {
    pub vna_hash: u32,
    pub vna_flags: u16,
    pub vna_other: u16,
    pub vna_name: u32,
    pub vna_next: u32,
}

#[cfg(test)]
mod test {
    use super::{ElfVernaux, ElfVerneed};
    use core::mem::size_of;

    #[test]
    fn check_size() {
        assert_eq!(16, size_of::<ElfVerneed>());
        assert_eq!(16, size_of::<ElfVernaux>());
    }
}

}
