// if the no_endian feature flag is set the libary will only be able to
// process files with the same endianess as the machine.
#[cfg(not(feature = "no_endian_fd"))]
extern crate byteorder;

#[macro_use] mod macros;

#[cfg(any(not(feature = "no_elf"), not(feature = "no_elf32")))]
pub mod elf;

// if racer gets path understanding, i think this is the way to go; it hides everything from the user w.r.t. module internals like _64, etc.
// though i did like the more declarative version below, without using paths, i just for the life of me cannot get the compiler to reexport values two mods down while keeping the internal mod name private... and i don't see anyone else doing this
#[cfg(not(feature = "no_elf"))]
#[path = "elf/_64/mod.rs"] pub mod elf64;

#[cfg(not(feature = "no_elf32"))]
#[path = "elf/_32/mod.rs"] pub mod elf32;

// #[cfg(not(feature = "no_elf"))]
// pub mod elf64 {
//      pub use elf::_64::*;
// }


// #[cfg(not(feature = "no_elf32"))]
// pub mod elf32 {
//      pub use elf::_32::*;
// }

#[cfg(not(feature = "no_mach"))]
pub mod mach;
