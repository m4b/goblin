//TODO: peek the io file instead of using fully parsed buffer
//use std::fs::File;
use std::io;
use scroll;

/// Returns a little endian magical number; be careful as this will alter the seek on the `buffer`
pub fn peek_magic<S: scroll::Scroll>(buffer: &S) -> io::Result<u32> {
    buffer.read_u32(&mut 0, true)
}
