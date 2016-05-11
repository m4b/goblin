use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom::Start;
use std::io;
use std::ops::Index;
use std::slice;
use std::str;
use std::fmt;

pub struct Strtab<'a> {
    bytes: &'a [u8],
}

#[inline(always)]
fn get_str<'a>(idx: usize, bytes: &'a [u8]) -> &str {
    let mut i = idx;
    let len = bytes.len();
    // hmmm, once exceptions are working correctly, maybe we should let this fail with i >= len?
    if i <= 0 || i >= len {
        return "";
    }
    let mut byte = bytes[i];
    while byte != 0 && i < bytes.len() {
        byte = bytes[i];
        i += 1;
    }
    if i > 0 {
        i -= 1;
    } // this isn't still quite right
    str::from_utf8(&bytes[idx..i]).unwrap()
}

impl<'a> Index<usize> for Strtab<'a> {
    type Output = str;

    fn index(&self, _index: usize) -> &Self::Output {
        get_str(_index, self.bytes)
    }
}

impl<'a> fmt::Debug for Strtab<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", str::from_utf8(&self.bytes))
    }
}

impl<'a> Strtab<'a> {
    pub unsafe fn from_raw(bytes_ptr: *const u8, size: usize) -> Strtab<'a> {
        Strtab { bytes: slice::from_raw_parts(bytes_ptr, size) }
    }

    pub fn from_fd(fd: &mut File, offset: usize, len: usize) -> io::Result<Strtab<'a>> {
        let mut bytes = vec![0u8; len];
        try!(fd.seek(Start(offset as u64)));
        try!(fd.read(&mut bytes));
        Ok(Strtab { bytes: unsafe { slice::from_raw_parts(bytes.as_ptr(), len) } })
    }

    /// Thanks to reem on #rust for this suggestion
    pub fn get(&self, idx: usize) -> &'a str {
        get_str(idx, self.bytes)
    }
}
