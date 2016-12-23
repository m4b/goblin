//TODO: peek the io file instead of using fully parsed buffer
//use std::fs::File;
use std::io;
use scroll;

/// Returns a native endian magical number
pub fn peek_magic<S: scroll::Gread>(buffer: &S) -> io::Result<u32> {
    buffer.gread(&mut 0, scroll::NATIVE)
}
