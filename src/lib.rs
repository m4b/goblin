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
//! * a "pure" mode which includes no io, no std, and no fun!
//! * a non-endian fd reading mode (which reads in the host machines endianness, for loaders)
//! * cfg switches to turn off unused
//! binary formats (when relocation and binary size are important (ideally, in the future this
//! won't be necessary if the compiler and/or linker can guarantee the unused symbols are dropped
//! in the final artifact)
//!
//! # Using the features
//! For example, if you are writing a kernel, or just want a barebones C-like
//! header interface which defines the structures, enable the pure feature, `--cfg
//! feature=\"pure\"`, which will turn off `std` and remove all extra methods defined on the
//! structs.
//!
//! Similarly, if you want to use host endianness loading via the various `from_fd` methods, `--cfg
//! feature=\"no_endian_fd\"`, which will not use the `byteorder` extern crate, and read the bytes
//! from disk in the endianness of the host machine.

#![cfg_attr(feature = "pure", no_std)]

// if the no_endian feature flag is set the libary will only be able to
// process files with the same endianess as the machine.
#[cfg(not(feature = "no_endian_fd"))]
extern crate byteorder;

#[macro_use]
mod macros;

#[cfg(any(not(feature = "no_elf"), not(feature = "no_elf32")))]
#[macro_use]
pub mod elf;

// if racer gets path understanding, i think this is the way to go; it hides everything from the
// user w.r.t. module internals like _64, etc.  though i did like the more declarative version
// below, without using paths, i just for the life of me cannot get the compiler to reexport values
// two mods down while keeping the internal mod name private... and i don't see anyone else doing
// this
#[cfg(not(feature = "no_elf"))]
#[path = "elf/_64/mod.rs"]
pub mod elf64;

#[cfg(not(feature = "no_elf32"))]
#[path = "elf/_32/mod.rs"]
pub mod elf32;

#[cfg(not(feature = "no_mach"))]
pub mod mach;
