// if the no_endian feature flag is set the libary will only be able to
// process files with the same endianess as the machine.
#[cfg(not(feature = "no_endian_fd"))]
extern crate byteorder;

// disjunkt so hard
#[cfg(any(not(feature = "no_elf"), not(feature = "no_elf32")))]
mod elves;

#[cfg(not(feature = "no_elf"))]
pub mod elf64 {
    pub use elves::_64::*;
}

#[cfg(not(feature = "no_elf32"))]
pub mod elf32 {
    pub use elves::_32::*;
}

#[cfg(not(feature = "no_mach"))]
pub mod mach;
