//! # libgoblin
//!
//! ![say the right
//! words](https://s-media-cache-ak0.pinimg.com/736x/1b/6a/aa/1b6aaa2bae005e2fed84b1a7c32ecb1b.jpg)
//!
//! `libgoblin` is a cross-platform trifecta of binary parsing and loading fun.  Currently, it supports:
//!
//! * the ELF32/64 formats
//! * A Unix archive parser and loader
//! * A PE 32-bit parser
//! * The mach parser is in progress
//!
//! Goblin requires at least `rustc` 1.15
//!
//! # Example
//!
//! ```rust
//! use goblin::{error, Hint, pe, elf, mach, archive};
//! use std::path::Path;
//! use std::env;
//! use std::fs::File;
//! use std::io::Read;
//!
//! fn run () -> error::Result<()> {
//!     for (i, arg) in env::args().enumerate() {
//!         if i == 1 {
//!             let path = Path::new(arg.as_str());
//!             let mut fd = File::open(path)?;
//!             let peek = goblin::peek(&mut fd)?;
//!             let mut buffer = Vec::new();
//!             fd.read_to_end(&mut buffer)?;
//!             match peek {
//!                 Hint::Elf(_) => {
//!                     let elf = elf::Elf::parse(&buffer)?;
//!                     println!("elf: {:#?}", &elf);
//!                 },
//!                 Hint::PE => {
//!                     let pe = pe::PE::parse(&buffer)?;
//!                     println!("pe: {:#?}", &pe);
//!                 },
//!                 // wip
//!                 Hint::Mach(_) => {
//!                     let mach = mach::Mach::parse(&buffer)?;
//!                     println!("mach: {:#?}", &mach);
//!                 },
//!                 Hint::Archive => {
//!                     let archive = archive::Archive::parse(&buffer)?;
//!                     println!("archive: {:#?}", &archive);
//!                 },
//!                 _ => {}
//!             }
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Feature Usage
//!
//! `libgoblin` is engineered to be tailored towards very different use-case scenarios, for example:
//!
//! * a no-std mode; just simply set default features to false
//! * a endian aware parsing and reading
//! * for binary loaders which don't require this, simply use `elf32` and `elf64` (and `std` of course)
//!
//! For example, if you are writing a 64-bit kernel, or just want a barebones C-like
//! header interface which defines the structures, just select `elf64`, `--cfg
//! feature=\"elf64\"`, which will compile without `std`.
//!
//! Similarly, if you want to use host endianness loading via the various `from_fd` methods, `--cfg
//! feature=\"std\"`, which will not use the `byteorder` extern crate, and read the bytes
//! from disk in the endianness of the host machine.
//!
//! If you want endian aware reading, and you don't use `default`, then you need to opt in as normal
//! via `endian_fd`

#![cfg_attr(not(feature = "std"), no_std)]

extern crate plain;
extern crate scroll;

#[cfg(feature = "std")]
extern crate core;

#[cfg(feature = "std")]
#[macro_use] extern crate scroll_derive;

#[cfg(feature = "std")]
pub mod error;

#[cfg(feature = "std")]
pub mod strtab;

/////////////////////////
// Misc/Helper Modules
/////////////////////////

/// Binary container size information and byte-order context
pub mod container {
    use scroll;
    #[derive(Debug, Copy, Clone, PartialEq)]
    pub enum Container {
        Little,
        Big,
    }

    #[cfg(not(target_pointer_width = "64"))]
    pub const CONTAINER: Container =  Container::Little;

    #[cfg(target_pointer_width = "64")]
    pub const CONTAINER: Container =  Container::Big;

    impl Default for Container {
        #[inline]
        fn default() -> Self {
            CONTAINER
        }
    }

    #[derive(Debug, Copy, Clone, PartialEq)]
    pub struct Ctx {
        pub container: Container,
        pub le: scroll::Endian,
    }

    impl Ctx {
        pub fn new (container: Container, le: scroll::Endian) -> Self {
            Ctx { container: container, le: le }
        }
        pub fn size(&self) -> usize {
            match self.container {
                // TODO: require pointer size initialization/setting or default to container size with these values, e.g., avr pointer width will be smaller iirc
                Container::Little => 4,
                Container::Big    => 8,
            }
        }
    }

    impl From<Container> for Ctx {
        fn from(container: Container) -> Self {
            Ctx { container: container, le: scroll::Endian::default() }
        }
    }

    impl From<scroll::Endian> for Ctx {
        fn from(le: scroll::Endian) -> Self {
            Ctx { container: CONTAINER, le: le }
        }
    }

    impl Default for Ctx {
        #[inline]
        fn default() -> Self {
            Ctx { container: Container::default(), le: scroll::Endian::default() }
        }
    }
}

#[cfg(feature = "std")]
pub use peek::*;

#[cfg(all(feature = "std"))]
mod peek {

    #[derive(Debug, Default)]
    /// Information obtained from a peek `Hint`
    pub struct HintData {
        pub is_lsb: bool,
        pub is_64: Option<bool>,
    }

    #[derive(Debug)]
    /// A hint at the underlying binary format for 16 bytes of arbitrary data
    pub enum Hint {
        Elf(HintData),
        Mach(HintData),
        MachFat(usize),
        PE,
        Archive,
        Unknown(u64),
    }

    /// Peeks at `bytes`, and returns a `Hint`
    #[cfg(all(feature = "endian_fd", feature = "elf64", feature = "elf32", feature = "pe64", feature = "pe32", feature = "mach64", feature = "mach32", feature = "archive"))]
    pub fn peek_bytes(bytes: &[u8; 16]) -> super::error::Result<Hint> {
        use scroll::{Pread, BE};
        use super::*;
        if &bytes[0..elf::header::SELFMAG] == elf::header::ELFMAG {
            let class = bytes[elf::header::EI_CLASS];
            let is_lsb = bytes[elf::header::EI_DATA] == elf::header::ELFDATA2LSB;
            let is_64 =
                if class == elf::header::ELFCLASS64 {
                    Some (true)
                } else if class == elf::header::ELFCLASS32 {
                    Some (false)
                } else { None };

            Ok(Hint::Elf(HintData { is_lsb: is_lsb, is_64: is_64 }))
        } else if &bytes[0..archive::SIZEOF_MAGIC] == archive::MAGIC {
            Ok(Hint::Archive)
        } else if (&bytes[0..2]).pread::<u16>(0)? == pe::header::DOS_MAGIC {
            Ok(Hint::PE)
        } else {
            use mach::{fat, header};
            let magic = mach::peek(&bytes, 0)?;
            match magic {
                fat::FAT_MAGIC => {
                    // should probably verify this is always Big Endian...
                    let narchitectures = bytes.pread_with::<u32>(4, BE)? as usize;
                    Ok(Hint::MachFat(narchitectures))
                },
                header::MH_CIGAM_64 | header::MH_CIGAM | header::MH_MAGIC_64 | header::MH_MAGIC => {
                    let is_lsb = magic == header::MH_CIGAM || magic == header::MH_CIGAM_64;
                    let is_64 = magic == header::MH_MAGIC_64 || magic == header::MH_CIGAM_64;
                    Ok(Hint::Mach(HintData { is_lsb: is_lsb, is_64: Some(is_64) }))
                },
                // its something else
                _ => Ok(Hint::Unknown(bytes.pread::<u64>(0)?))
            }
        }
    }

    /// Peeks at the underlying Read object. Requires the underlying bytes to have at least 16 byte length. Resets the seek to `Start` after reading.
    #[cfg(all(feature = "endian_fd", feature = "elf64", feature = "elf32", feature = "pe64", feature = "pe32", feature = "mach64", feature = "mach32", feature = "archive"))]
    pub fn peek<R: ::std::io::Read + ::std::io::Seek>(fd: &mut R) -> super::error::Result<Hint> {
        use std::io::SeekFrom;
        let mut bytes = [0u8; 16];
        fd.seek(SeekFrom::Start(0))?;
        fd.read_exact(&mut bytes)?;
        fd.seek(SeekFrom::Start(0))?;
        peek_bytes(&bytes)
    }
}

/////////////////////////
// Binary Modules
/////////////////////////

#[cfg(any(feature = "elf64", feature = "elf32"))]
#[macro_use]
pub mod elf;

#[cfg(feature = "elf32")]
/// The ELF 32-bit struct definitions and associated values, re-exported for easy "type-punning"
pub mod elf32 {
    pub use elf::header::header32 as header;
    pub use elf::program_header::program_header32 as program_header;
    pub use elf::section_header::section_header32 as section_header;
    pub use elf::dyn::dyn32 as dyn;
    pub use elf::sym::sym32 as sym;
    pub use elf::reloc::reloc32 as reloc;

    #[cfg(feature = "std")]
    pub use strtab;

    #[cfg(feature = "std")]
    pub mod gnu_hash {
        elf_gnu_hash_impl!(u32);
    }
}

#[cfg(feature = "elf64")]
/// The ELF 64-bit struct definitions and associated values, re-exported for easy "type-punning"
pub mod elf64 {
    pub use elf::header::header64 as header;
    pub use elf::program_header::program_header64 as program_header;
    pub use elf::section_header::section_header64 as section_header;
    pub use elf::dyn::dyn64 as dyn;
    pub use elf::sym::sym64 as sym;
    pub use elf::reloc::reloc64 as reloc;

    #[cfg(feature = "std")]
    pub use strtab;

    #[cfg(feature = "std")]
    pub mod gnu_hash {
        elf_gnu_hash_impl!(u64);
    }
}

#[cfg(feature = "mach64")]
pub mod mach;

#[cfg(all(feature = "archive", feature = "std"))]
pub mod archive;

#[cfg(all(feature = "pe32", feature = "std"))]
pub mod pe;
