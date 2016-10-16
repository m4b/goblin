use core::ops::Index;
use core::slice;
use core::str;
use core::fmt;
use std::borrow::Cow;

pub struct Strtab<'a> {
    // Thanks to SpaceManiac and Mutabah on #rust for suggestion and debugging this
    bytes: Cow<'a, [u8]>,
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

impl<'a> Default for Strtab<'a> {
    fn default() -> Strtab<'static> {
        Strtab { bytes: Cow::Owned(vec![]) }
    }
}

impl<'a> Index<usize> for Strtab<'a> {
    type Output = str;

    fn index(&self, _index: usize) -> &Self::Output {
        get_str(_index, &self.bytes)
    }
}

impl<'a> fmt::Debug for Strtab<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", str::from_utf8(&self.bytes))
    }
}

#[cfg(feature = "std")]
pub use self::impure::*;

#[cfg(feature = "std")]
mod impure {
    use std::io::{self, Read, Seek};
    use std::io::SeekFrom::Start;
    use std::borrow::Cow;
    use super::*;

    impl<'a> Strtab<'a> {
        pub fn parse<R: Read + Seek>(fd: &mut R, offset: usize, len: usize) -> io::Result<Strtab<'static>> {
            let mut bytes = vec![0u8; len];
            try!(fd.seek(Start(offset as u64)));
            try!(fd.read(&mut bytes));
            Ok(Strtab { bytes: Cow::Owned(bytes) })
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
}

impl<'a> Strtab<'a> {
    pub unsafe fn from_raw(bytes_ptr: *const u8, size: usize) -> Strtab<'a> {
        Strtab { bytes: Cow::Borrowed(slice::from_raw_parts(bytes_ptr, size)) }
    }

    // Thanks to reem on #rust for this suggestion
    pub fn get(&'a self, idx: usize) -> &'a str {
        get_str(idx, &self.bytes)
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
