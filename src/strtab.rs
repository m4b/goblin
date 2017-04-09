//! A byte-offset based string table.
//! Commonly used in ELF binaries, and also archives.

use core::ops::Index;
use core::slice;
use core::str;
use core::fmt;
use scroll::{ctx, Pread};
#[cfg(feature = "std")]
use error;

/// A common string table format which is indexed by byte offsets (and not
/// member index). Constructed using [`parse`](#method.parse)
/// with your choice of delimiter. Please be careful.
pub struct Strtab<'a> {
    bytes: &'a[u8],
    delim: ctx::StrCtx,
}

#[inline(always)]
fn get_str(idx: usize, bytes: &[u8], delim: ctx::StrCtx) -> &str {
    bytes.pread_with::<&str>(idx, delim).unwrap()
}

impl<'a> Strtab<'a> {
    pub fn new (bytes: &'a [u8], delim: u8) -> Self {
        Strtab { delim: ctx::StrCtx::from(delim), bytes: bytes }
    }
    pub unsafe fn from_raw(bytes_ptr: *const u8, size: usize, delim: u8) -> Strtab<'a> {
        Strtab { delim: ctx::StrCtx::from(delim), bytes: slice::from_raw_parts(bytes_ptr, size) }
    }
    #[cfg(feature = "std")]
    pub fn parse(bytes: &'a [u8], offset: usize, len: usize, delim: u8) -> error::Result<Strtab<'a>> {
        let bytes: &'a [u8] = bytes.pread_slice(offset, len)?;
        Ok(Strtab { bytes: bytes, delim: ctx::StrCtx::from(delim) })
    }
    #[cfg(feature = "std")]
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
    // Thanks to reem on #rust for this suggestion
    pub fn get(&'a self, idx: usize) -> &'a str {
        get_str(idx, &self.bytes, self.delim)
    }
}

impl<'a> fmt::Debug for Strtab<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "delim: {:?} {:?}", self.delim, str::from_utf8(&self.bytes))
    }
}

impl<'a> Default for Strtab<'a> {
    fn default() -> Strtab<'a> {
        Strtab { bytes: &[], delim: ctx::StrCtx::default() }
    }
}

impl<'a> Index<usize> for Strtab<'a> {
    type Output = str;

    fn index(&self, _index: usize) -> &Self::Output {
        get_str(_index, &self.bytes, self.delim)
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
