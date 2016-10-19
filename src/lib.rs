//! # libgoblin
//!
//! ![say the right
//! words](https://s-media-cache-ak0.pinimg.com/736x/1b/6a/aa/1b6aaa2bae005e2fed84b1a7c32ecb1b.jpg)
//!
//! `libgoblin` is a cross-platform trifecta of binary parsing and loading fun.  Currently, it only
//! supports the ELF format, in both 32-bit and 64-bit variants (with especial bias towards 64-bit
//! formats).  The mach parser is in progress, and the PE format will follow.  `libgoblin` is
//! engineered to be tailored towards very different use-case scenarios, for example:
//!
//! * a no-std mode; just simply set default features to false
//! * a endian aware parsing and reading
//! * for binary loaders which don't require this, simply use `elf32` and `elf64` (and `std` of course)
//!
//! # Example Feature Usage
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
extern crate byteorder;

#[cfg(feature = "std")]
extern crate core;

#[macro_use]
mod macros;

#[cfg(any(feature = "elf64", feature = "elf64"))]
#[macro_use]
pub mod elf;

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
