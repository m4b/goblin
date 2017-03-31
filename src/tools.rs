
pub trait Slice {
    /// Converts slice of one type into a slice of another,
    /// automatically determining appropriate length.
    ///
    /// == Safety ==
    /// This function is safe as long as the result type is
    /// a Copy type and doesn't have any invalid values.
    /// In particular, the result type shouldn't contain any
    /// bool or enum value.
    ///
    unsafe fn retype<T>(&self) -> &[T]
        where T: Copy;

    /// Converts slice of one type into a slice of another,
    /// with output length provided as argument.
    ///
    /// == Safety ==
    /// This function is safe as long as the result type is
    /// a Copy type and doesn't have any invalid values.
    /// In particular, the result type shouldn't contain any
    /// bool or enum value.
    ///
    /// == Panics ==
    /// The function will panic if the requested length 
    /// can't be satisfied by input slice.
    ///
    unsafe fn retype_with_len<T>(&self, len: usize) -> &[T]
        where T: Copy;

    /// Converts a slice to a slice of bytes.
    fn as_bytes(&self) -> &[u8];
    
    /// Converts a slice into a mutable slice of bytes,
    /// allowing direct access to the former's representation in memory.
    ///
    /// == Safety ==
    /// It is not safe to modify bytes that correspond to types with
    /// invalid values. In particular, the input slice shouldn't contain values
    /// of bool or enum types. If such values are present, they must not be
    /// modified in a way that results in invalid values.
    ///
    unsafe fn as_mut_bytes(&mut self) -> &mut [u8];
}

use core::mem::size_of;
use core::slice::{from_raw_parts, from_raw_parts_mut};

impl<S> Slice for [S] {
    unsafe fn retype<T>(&self) -> &[T]
        where T: Copy {

        let byte_len = self.len() * size_of::<S>();
        let new_len = byte_len / size_of::<T>();
        from_raw_parts(self.as_ptr() as *const T, new_len)
    }

    unsafe fn retype_with_len<T>(&self, len: usize) -> &[T]
        where T: Copy {

        let byte_len = self.len() * size_of::<S>();
        let new_len = byte_len / size_of::<T>();
        assert!(len <= new_len);	
        from_raw_parts(self.as_ptr() as *const T, len)
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFE: So long as the slice is immutable, and we don't overshoot the length,
        // it is safe to view the memory as bytes.
        unsafe {
            from_raw_parts(self.as_ptr() as *const u8, self.len() * size_of::<S>())
        }
    }
    
    unsafe fn as_mut_bytes(&mut self) -> &mut [u8] {
        from_raw_parts_mut(self.as_mut_ptr() as *mut u8, self.len() * size_of::<S>())
    }
}

