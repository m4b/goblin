use std::fs::File;
use std::io;

use byteorder::{LittleEndian, ReadBytesExt};

/// Returns a little endian magical number; be careful as this will alter the seek on the `fd`
pub fn peek_magic(fd: &mut File) -> io::Result<u32> {
    fd.read_u32::<LittleEndian>()
}
