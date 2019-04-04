// Defined note types for GNU systems.

#[cfg(feature = "log")]
use log::debug;
#[cfg(feature = "alloc")]
use scroll::{IOread, IOwrite, Pread, Pwrite, SizeWith};

// ABI information.  The descriptor consists of words:
//    word 0: OS descriptor
//    word 1: major version of the ABI
//    word 2: minor version of the ABI
//    word 3: subminor version of the ABI

pub const NT_GNU_ABI_TAG: u32 = 1;
// Old name
pub const ELF_NOTE_ABI: u32 = NT_GNU_ABI_TAG;
// Known OSes.  These values can appear in word 0 of an
//    NT_GNU_ABI_TAG note section entry.
pub const ELF_NOTE_OS_LINUX: u32 = 0;
pub const ELF_NOTE_OS_GNU: u32 = 1;
pub const ELF_NOTE_OS_SOLARIS2: u32 = 2;
pub const ELF_NOTE_OS_FREEBSD: u32 = 3;

// Synthetic hwcap information.  The descriptor begins with two words:
//    word 0: number of entries
//    word 1: bitmask of enabled entries
//    Then follow variable-length entries, one byte followed by a
//    '\0'-terminated hwcap name string.  The byte gives the bit
//    number to test if enabled, (1U << bit) & bitmask.
pub const NT_GNU_HWCAP: u32 = 2;

// Build ID bits as generated by ld --build-id.
//    The descriptor consists of any nonzero number of bytes.
pub const NT_GNU_BUILD_ID: u32 = 3;

// Version note generated by GNU gold containing a version string.
pub const NT_GNU_GOLD_VERSION: u32 = 4;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "alloc", derive(Pread, Pwrite, IOread, IOwrite, SizeWith))]
#[repr(C)]
/// Note section contents. Each entry in the note section begins with a header of a fixed form.
pub struct Nhdr32 {
    /// Length of the note's name (includes the terminator)
    pub n_namesz: u32,
    /// Length of the note's descriptor
    pub n_descsz: u32,
    /// Type of the note
    pub n_type: u32,
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "alloc", derive(Pread, Pwrite, IOread, IOwrite, SizeWith))]
#[repr(C)]
/// Note section contents. Each entry in the note section begins with a header of a fixed form.
pub struct Nhdr64 {
    /// Length of the note's name (includes the terminator)
    pub n_namesz: u64,
    /// Length of the note's descriptor.
    pub n_descsz: u64,
    /// Type of the note.
    pub n_type: u64,
}

if_alloc! {
    use crate::error;
    use crate::container;
    use scroll::ctx;
    use crate::alloc::vec::Vec;

    /// An iterator over ELF binary notes in a note section or segment
    pub struct NoteDataIterator<'a> {
        pub data: &'a [u8],
        pub size: usize,
        pub offset: usize,
        pub ctx: (usize, container::Ctx), // (alignment, ctx)
    }

    impl<'a> Iterator for NoteDataIterator<'a> {
        type Item = error::Result<Note<'a>>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.offset >= self.size {
                None
            } else {
                debug!("NoteIterator - {:#x}", self.offset);
                match self.data.gread_with(&mut self.offset, self.ctx) {
                    Ok(res) => Some(Ok(res)),
                    Err(e) => Some(Err(e))
                }
            }
        }
    }

    /// An iterator over ELF binary notes
    pub struct NoteIterator<'a> {
        pub iters: Vec<NoteDataIterator<'a>>,
        pub index: usize,
    }

    impl<'a> Iterator for NoteIterator<'a> {
        type Item = error::Result<Note<'a>>;
        fn next(&mut self) -> Option<Self::Item> {
            while self.index < self.iters.len() {
                if let Some(note_result) = self.iters[self.index].next() {
                    return Some(note_result);
                }

                self.index += 1;
            }

            None
        }
    }

    #[derive(Debug)]
    struct NoteHeader {
        n_namesz: usize,
        n_descsz: usize,
        n_type: u32,
    }

    impl From<Nhdr32> for NoteHeader {
        fn from(header: Nhdr32) -> Self {
            NoteHeader {
                n_namesz: header.n_namesz as usize,
                n_descsz: header.n_descsz as usize,
                n_type: header.n_type,
            }
        }
    }

    impl From<Nhdr64> for NoteHeader {
        fn from(header: Nhdr64) -> Self {
            NoteHeader {
                n_namesz: header.n_namesz as usize,
                n_descsz: header.n_descsz as usize,
                n_type: header.n_type as u32,
            }
        }
    }

    fn align(alignment: usize, offset: &mut usize) {
        let diff = *offset % alignment;
        if diff != 0 {
            *offset += alignment - diff;
        }
    }

    /// A 32/64 bit Note struct, with the name and desc pre-parsed
    #[derive(Debug)]
    pub struct Note<'a> {
        /// The type of this note
        pub n_type: u32,
        /// NUL terminated string, where `namesz` includes the terminator
        pub name: &'a str, // needs padding such that namesz + padding % {wordsize} == 0
        /// arbitrary data of length `descsz`
        pub desc: &'a [u8], // needs padding such that descsz + padding % {wordsize} == 0
    }

    impl<'a> Note<'a> {
        pub fn type_to_str(&self) -> &'static str {
            match self.n_type {
                NT_GNU_ABI_TAG => "NT_GNU_ABI_TAG",
                NT_GNU_HWCAP => "NT_GNU_HWCAP",
                NT_GNU_BUILD_ID => "NT_GNU_BUILD_ID",
                NT_GNU_GOLD_VERSION => "NT_GNU_GOLD_VERSION",
                _ => "NT_UNKNOWN"
            }
        }
    }

    impl<'a> ctx::TryFromCtx<'a, (usize, container::Ctx)> for Note<'a> {
        type Error = error::Error;
        type Size = usize;
        fn try_from_ctx(bytes: &'a [u8], (alignment, ctx): (usize, container::Ctx)) -> Result<(Self, Self::Size), Self::Error> {
            let offset = &mut 0;
            let mut alignment = alignment;
            if alignment < 4 {
                alignment = 4;
            }
            let header: NoteHeader = {
                match alignment {
                    4|8 => bytes.gread_with::<Nhdr32>(offset, ctx.le)?.into(),
                    _ => return Err(error::Error::Malformed(format!("Notes has unimplemented alignment requirement: {:#x}", alignment)))
                }
            };
            debug!("{:?} - {:#x}", header, *offset);
            // -1 because includes \0 terminator
            let name = bytes.gread_with::<&'a str>(offset, ctx::StrCtx::Length(header.n_namesz - 1))?;
            *offset += 1;
            align(alignment, offset);
            debug!("note name {} - {:#x}", name, *offset);
            let desc = bytes.gread_with::<&'a [u8]>(offset, header.n_descsz)?;
            align(alignment, offset);
            debug!("desc {:?} - {:#x}", desc, *offset);
            Ok((Note {
                name,
                desc,
                n_type: header.n_type,
            }, *offset))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        static NOTE_DATA: [u8; 68] = [0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                                     0x01, 0x00, 0x00, 0x00, 0x47, 0x4e, 0x55, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                                     0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
                                     0x04, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
                                     0x03, 0x00, 0x00, 0x00, 0x47, 0x4e, 0x55, 0x00,
                                     0xbc, 0xfc, 0x66, 0xcd, 0xc7, 0xd5, 0x14, 0x7b,
                                     0x53, 0xb1, 0x10, 0x11, 0x94, 0x86, 0x8e, 0xf9,
                                     0x4f, 0xe8, 0xdd, 0xdb];

        static CONTEXT: (usize, container::Ctx) = (4, container::Ctx {
            container: container::Container::Big,
            le: ::scroll::Endian::Little,
        });

        fn make_note_iter(start: usize, end: usize) -> NoteDataIterator<'static> {
            NoteDataIterator {
                data: &NOTE_DATA,
                size: end,
                offset: start,
                ctx: CONTEXT,
            }
        }

        #[test]
        fn iter_single_section() {
            let mut notes = NoteIterator {
                iters: vec![make_note_iter(0, 68)],
                index: 0,
            };

            assert_eq!(notes.next().unwrap().unwrap().n_type, NT_GNU_ABI_TAG);
            assert_eq!(notes.next().unwrap().unwrap().n_type, NT_GNU_BUILD_ID);
            assert!(notes.next().is_none());
        }

        #[test]
        fn iter_multiple_sections() {
            let mut notes = NoteIterator {
                iters: vec![make_note_iter(0, 32), make_note_iter(32, 68)],
                index: 0,
            };

            assert_eq!(notes.next().unwrap().unwrap().n_type, NT_GNU_ABI_TAG);
            assert_eq!(notes.next().unwrap().unwrap().n_type, NT_GNU_BUILD_ID);
            assert!(notes.next().is_none());
        }

        #[test]
        fn skip_empty_sections() {
            let mut notes = NoteIterator {
                iters: vec![
                    make_note_iter(0, 32),
                    make_note_iter(0, 0),
                    make_note_iter(32, 68),
                ],
                index: 0,
            };

            assert_eq!(notes.next().unwrap().unwrap().n_type, NT_GNU_ABI_TAG);
            assert_eq!(notes.next().unwrap().unwrap().n_type, NT_GNU_BUILD_ID);
            assert!(notes.next().is_none());
        }

        #[test]
        fn ignore_no_sections() {
            let mut notes = NoteIterator { iters: vec![], index: 0 };
            assert!(notes.next().is_none());
        }
    }
}
