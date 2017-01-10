//TODO: peek the io file instead of using fully parsed buffer
//use std::fs::File;
//use std::io;
use scroll;
use error;

/// Returns a native endian magical number
pub fn peek_magic<S: scroll::Gread>(buffer: &S) -> error::Result<u32> {
    Ok(buffer.gread::<u32>(&mut 0, scroll::NATIVE)?)
}
