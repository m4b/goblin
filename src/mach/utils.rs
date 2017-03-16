//TODO: peek the io file instead of using fully parsed buffer
//use std::fs::File;
//use std::io;
use scroll::{self, Pread};
use error;

/// Returns a big endian magical number
pub fn peek_magic<S: AsRef<[u8]>>(buffer: &S, offset: usize) -> error::Result<u32> {
    Ok(buffer.pread_with::<u32>(offset, scroll::BE)?)
}
