// if the no_endian feature flag is set the libary will only be able to
// process files with the same endianess as the machine.
#[cfg(not(feature = "no_endian_fd"))]
extern crate byteorder;

// for now only switches on elf 64 bit variants; need to figure that out
// this kind of nonsense: elf::header32
#[cfg(not(feature = "no_elf"))]
pub mod elf;

#[cfg(not(feature = "no_mach"))]
pub mod mach;

#[cfg(not(feature = "no_elf32"))]
pub mod elf32;
