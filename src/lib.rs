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
//!
//! fn run () -> error::Result<()> {
//!     for (i, arg) in env::args().enumerate() {
//!         if i == 1 {
//!             let path = Path::new(arg.as_str());
//!             let mut fd = File::open(path)?;
//!             match goblin::peek(&mut fd)? {
//!                 Hint::Elf(_) => {
//!                     let elf = elf::Elf::try_from(&mut fd)?;
//!                     println!("elf: {:#?}", &elf);
//!                 },
//!                 Hint::PE => {
//!                     let pe = pe::PE::try_from(&mut fd)?;
//!                     println!("pe: {:#?}", &pe);
//!                 },
//!                 // wip
//!                 Hint::Mach => {
//!                     let mach = mach::Mach::try_from(&mut fd)?;
//!                     println!("mach: {:#?}", &mach);
//!                 },
//!                 Hint::Archive => {
//!                     let archive = archive::Archive::try_from(&mut fd)?;
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

// if the no_endian feature flag is set the libary will only be able to
// process files with the same endianess as the machine.
#[cfg(feature = "endian_fd")]
extern crate scroll;

#[cfg(feature = "endian_fd")]
#[macro_use]
extern crate scroll_derive;

#[cfg(feature = "std")]
extern crate core;

#[macro_use]
mod macros;

#[cfg(any(feature = "elf64", feature = "elf32"))]
#[macro_use]
pub mod elf;

#[cfg(feature = "std")]
pub mod error;

// if racer gets path understanding, i think this is the way to go; it hides everything from the
// user w.r.t. module internals like _64, etc.  though i did like the more declarative version
// below, without using paths, i just for the life of me cannot get the compiler to reexport values
// two mods down while keeping the internal mod name private... and i don't see anyone else doing
// this
#[cfg(feature = "elf64")]
#[path = "elf/_64/mod.rs"]
pub mod elf64;

#[cfg(feature = "elf32")]
#[path = "elf/_32/mod.rs"]
pub mod elf32;

#[cfg(feature = "mach64")]
pub mod mach;

#[cfg(feature = "archive")]
pub mod archive;

#[cfg(feature = "pe32")]
pub mod pe;

#[cfg(feature = "std")]
pub use impure::*;

#[cfg(all(feature = "std"))]
mod impure {

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
        Mach,
        PE,
        Archive,
        Unknown,
    }

    /// Peeks at the underlying Read object. Requires the underlying bytes to have at least 16 byte length. Resets the seek after reading.
#[cfg(all(feature = "endian_fd", feature = "elf64", feature = "elf32", feature = "pe64", feature = "pe32", feature = "mach64", feature = "mach32", feature = "archive"))]
    pub fn peek<R: ::std::io::Read + ::std::io::Seek>(fd: &mut R) -> super::error::Result<Hint> {
        use scroll::Pread;
        use std::io::SeekFrom;
        use super::*;
        let mut bytes = [0u8; 16];
        fd.seek(SeekFrom::Start(0))?;
        fd.read_exact(&mut bytes)?;
        fd.seek(SeekFrom::Start(0))?;
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
            Ok(Hint::Unknown)
        }
    }
}
