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
fn get_str(idx: usize, bytes: &[u8]) -> &str {
    let mut i = idx;
    let len = bytes.len();
    // hmmm, once exceptions are working correctly, maybe we should let this fail with i >= len?
    if i == 0 || i >= len {
        return "";
    }
    let mut byte = bytes[i];
    while byte != 0 && i < len {
        byte = bytes[i];
        i += 1;
    }
    // we drop the null terminator unless we're at the end and the byte isn't a null terminator
    if i < len || bytes[i - 1] == 0 {
        i -= 1;
    }
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
        // TODO: this creates a memory leak; if we don't forget the bytes (and not the reference), then the memory is dropped and we crash later
        // the problem is the strtab was meant to be used with mmap'd elements, and slices are easier to work with, but now we're expanding to an fd api with all-heap allocations...
        let ptr = bytes.as_ptr();
        ::std::mem::forget(bytes);
        let slice = unsafe { slice::from_raw_parts(ptr, len) };
        Ok(Strtab { bytes: slice })
    }

    // Thanks to reem on #rust for this suggestion
    pub fn get(&self, idx: usize) -> &'a str {
        get_str(idx, self.bytes)
    }

    pub fn to_vec(self) -> Vec<String> {
        let len = self.bytes.len();
        let mut strings = Vec::with_capacity(len);
        let mut i = 0;
        while i < len {
            let string = self.get(i);
            i = i + string.len() + 1;
            strings.push(string.to_string());
        }
        strings
    }
}

#[test]
fn as_vec_test_no_final_null() {
    let bytes = b"\0printf\0memmove\0busta";
    let strtab = unsafe { Strtab::from_raw(bytes.as_ptr(), bytes.len()) };
    let vec = strtab.to_vec();
    assert_eq!(vec.len(), 4);
}

#[test]
fn to_vec_test_final_null() {
    let bytes = b"\0printf\0memmove\0busta\0";
    let strtab = unsafe { Strtab::from_raw(bytes.as_ptr(), bytes.len()) };
    let vec = strtab.to_vec();
    assert_eq!(vec.len(), 4);
}
