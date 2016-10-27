//! A byte-offset based string table.
//! Commonly used in ELF binaries, and also archives.

use core::ops::Index;
use core::slice;
use core::str;
use core::fmt;
use std::borrow::Cow;

/// A common string table format which is indexed by byte offsets (and not
/// member index). Constructed using [`parse`](#method.parse)
/// with your choice of delimiter. Please be careful.
pub struct Strtab<'a> {
    // Thanks to SpaceManiac and Mutabah on #rust for suggestion and debugging this
    bytes: Cow<'a, [u8]>,
    delim: u8,
}

#[inline(always)]
fn get_str(idx: usize, bytes: &[u8], delim: u8) -> &str {
    let mut i = idx;
    let len = bytes.len();
    if i >= len {
        return "";
    }
    let mut byte = bytes[i];
    // TODO: this is still a hack and getting worse and worse
    if byte == delim {
        return "";
    }
    while byte != delim && i < len {
        byte = bytes[i];
        i += 1;
    }
    // we drop the null terminator unless we're at the end and the byte isn't a null terminator
    if i < len || bytes[i - 1] == delim {
        i -= 1;
    }
    str::from_utf8(&bytes[idx..i]).unwrap()
}

impl<'a> Default for Strtab<'a> {
    fn default() -> Strtab<'static> {
        Strtab { bytes: Cow::Owned(vec![]), delim: 0x0 }
    }
}

impl<'a> Index<usize> for Strtab<'a> {
    type Output = str;

    fn index(&self, _index: usize) -> &Self::Output {
        get_str(_index, &self.bytes, self.delim)
    }
}

impl<'a> fmt::Debug for Strtab<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "delim: {:?} {:?}", self.delim as char, str::from_utf8(&self.bytes))
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
        pub fn parse<R: Read + Seek>(fd: &mut R, offset: usize, len: usize, delim: u8) -> io::Result<Strtab<'static>> {
            let mut bytes = vec![0u8; len];
            try!(fd.seek(Start(offset as u64)));
            try!(fd.read(&mut bytes));
            Ok(Strtab { bytes: Cow::Owned(bytes), delim: delim })
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
    pub unsafe fn from_raw(bytes_ptr: *const u8, size: usize, delim: u8) -> Strtab<'a> {
        Strtab { delim: delim, bytes: Cow::Borrowed(slice::from_raw_parts(bytes_ptr, size)) }
    }

    // Thanks to reem on #rust for this suggestion
    pub fn get(&'a self, idx: usize) -> &'a str {
        get_str(idx, &self.bytes, self.delim)
    }
}

#[test]
fn as_vec_no_final_null() {
    let bytes = b"\0printf\0memmove\0busta";
    let strtab = unsafe { Strtab::from_raw(bytes.as_ptr(), bytes.len(), 0x0) };
    let vec = strtab.to_vec();
    assert_eq!(vec.len(), 4);
    assert_eq!(vec, vec!["", "printf", "memmove", "busta"]);
}

#[test]
fn as_vec_no_first_null_no_final_null() {
    let bytes = b"printf\0memmove\0busta";
    let strtab = unsafe { Strtab::from_raw(bytes.as_ptr(), bytes.len(), 0x0) };
    let vec = strtab.to_vec();
    assert_eq!(vec.len(), 3);
    assert_eq!(vec, vec!["printf", "memmove", "busta"]);
}

#[test]
fn to_vec_final_null() {
    let bytes = b"\0printf\0memmove\0busta\0";
    let strtab = unsafe { Strtab::from_raw(bytes.as_ptr(), bytes.len(), 0x0) };
    let vec = strtab.to_vec();
    assert_eq!(vec.len(), 4);
    assert_eq!(vec, vec!["", "printf", "memmove", "busta"]);
}

#[test]
fn to_vec_newline_delim() {
    let bytes = b"\nprintf\nmemmove\nbusta\n";
    let strtab = unsafe { Strtab::from_raw(bytes.as_ptr(), bytes.len(), '\n' as u8) };
    let vec = strtab.to_vec();
    assert_eq!(vec.len(), 4);
    assert_eq!(vec, vec!["", "printf", "memmove", "busta"]);
}
