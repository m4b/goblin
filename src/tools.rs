
use core::mem::size_of;
use core::slice::{from_raw_parts, from_raw_parts_mut};

/// Converts slice of one type into a slice of another,
/// automatically determining appropriate length.
///
/// == Safety ==
/// This function is safe as long as the result type is
/// a Copy type and doesn't have any invalid values.
/// In particular, the result type shouldn't contain any
/// bool or enum value.
///
pub unsafe fn retype_slice<'a, S, T>(slice: &'a[T]) -> &'a[S]
	where T: Copy, S: Copy
{
	let byte_len = slice.len() * size_of::<T>();
	let new_len = byte_len / size_of::<S>();
	from_raw_parts(slice.as_ptr() as *const S, new_len)
}

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
pub unsafe fn retype_slice_with_len<'a, S, T>(slice: &'a[T], len: usize) -> &'a[S]
	where T: Copy, S: Copy
{
	let byte_len = slice.len() * size_of::<T>();
	let new_len = byte_len / size_of::<S>();
	assert!(len <= new_len);	
	from_raw_parts(slice.as_ptr() as *const S, len)
}

/// Converts a slice of any Copy type into a slice of bytes,
/// allowing direct access to the former's representation in memory.
///
/// == Safety ==
/// It is not safe to modify bytes that correspond to types with
/// invalid values. In particular, the input slice shouldn't contain values
/// of bool or enum types. If such values are present, they must not be
/// modified in a way that results in invalid values.
///
pub unsafe fn as_bytes_mut<'a, T>(slice: &'a mut [T]) -> &'a mut [u8]
	where T: Copy
{
	let byte_len = slice.len() * size_of::<T>();
	from_raw_parts_mut(slice.as_mut_ptr() as *mut u8, byte_len)
}