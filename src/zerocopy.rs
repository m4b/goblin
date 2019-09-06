//! This module is heavily inspired by the `::zerocopy` crate,
//! whose LICENSE states the following (BSD-3-Clause):
/*!
    Copyright 2019 The Fuchsia Authors. All rights reserved.
    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:
    * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following disclaimer
    in the documentation and/or other materials provided with the
    distribution.
    * Neither the name of Google Inc. nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//! The trick is that it does not use syn / quote, just plain old macro_rules!

macro_rules! impl_macro {
    (
        unsafe
        impl $Trait:path, for numeric_types!() $(;)?
    ) => (
        impl_macro!(@impl_for_all
            unsafe
            impl $Trait, for [
                u8,     i8,
                u16,    i16,
                u32,    i32,
                usize,  isize,
                u64,    i64,
                u128,   i128,
            /* In practice these are not used */
                // f32,
                // f64,
            ]
        );
    );

    (
        unsafe
        impl $Trait:path, for composite_types!() $(;)?
    ) => (
        impl_macro!(@impl_for_all
            unsafe
            impl $Trait, for [
                {T : $Trait} [T],
            /* In practice these are not used */
                // (),
                // {
                //     T1 : $Trait,
                // } (T1,),
                // {
                //     T1 : $Trait,
                //     T2 : $Trait,
                // } (T1, T2,),
                // {
                //     T1 : $Trait,
                //     T2 : $Trait,
                //     T3 : $Trait,
                // } (T1, T2, T3,),
                // {
                //     T1 : $Trait,
                //     T2 : $Trait,
                //     T3 : $Trait,
                //     T4 : $Trait,
                // } (T1, T2, T3, T4,),
                // {T : ?Sized} ::core::marker::PhantomData<T>,
            ]
        );
        impl_macro!(
            unsafe
            impl $Trait, for array_types!()
        );
    );

    (
        unsafe
        impl $Trait:path, for array_types!() $(;)?
    ) => (
        impl_macro!(@impl_for_all
            unsafe
            impl $Trait, for [
            /* In practice these are not used */
                // {T : $Trait} [T;    0],
                // {T : $Trait} [T;    1],
                {T : $Trait} [T;    2],
                {T : $Trait} [T;    3],
                {T : $Trait} [T;    4],
            /* In practice these are not used */
                // {T : $Trait} [T;    5],
                // {T : $Trait} [T;    6],
                // {T : $Trait} [T;    7],
                // {T : $Trait} [T;    8],
                // {T : $Trait} [T;    9],
                // {T : $Trait} [T;   10],
                // {T : $Trait} [T;   11],
                // {T : $Trait} [T;   12],
                // {T : $Trait} [T;   13],
                // {T : $Trait} [T;   14],
                // {T : $Trait} [T;   15],
                // {T : $Trait} [T;   16],
                // {T : $Trait} [T;   17],
                // {T : $Trait} [T;   18],
                // {T : $Trait} [T;   19],
                // {T : $Trait} [T;   20],
                // {T : $Trait} [T;   21],
                // {T : $Trait} [T;   22],
                // {T : $Trait} [T;   23],
                // {T : $Trait} [T;   24],
                // {T : $Trait} [T;   25],
                // {T : $Trait} [T;   26],
                // {T : $Trait} [T;   27],
                // {T : $Trait} [T;   28],
                // {T : $Trait} [T;   29],
                // {T : $Trait} [T;   30],
                // {T : $Trait} [T;   31],
                // {T : $Trait} [T;   32],
                // {T : $Trait} [T;   64],
                // {T : $Trait} [T;  128],
                // {T : $Trait} [T;  256],
                // {T : $Trait} [T;  512],
                // {T : $Trait} [T; 1024],
                // {T : $Trait} [T; 2048],
                // {T : $Trait} [T; 4096],
            ]
        );
    );

    (@impl_for_all
        unsafe
        impl $Trait:path, for [
            $(
                $({$($generics:tt)*})? $T:ty
            ),* $(,)?
        ] $(;)?
    ) => (
        $(
            impl_macro!(
                unsafe
                impl $Trait, for $({$($generics)*})? $T
            );
        )*
    );

    (
        unsafe
        impl $Trait:path, for $({$($generics:tt)*})? $T:ty $(;)?
    ) => (
        unsafe
        impl $(<$($generics)*>)? $Trait for $T {}
    );
}

/// Unsafe marker trait for types that are valid for any byte-pattern.
///
/// This is true of primitive types, and recursively for `#[repr(C)]`
/// compositions of such types (such as arrays).
///
/// The derive macro takes care of deriving this trait with the necessary
/// compile-time guards.
pub(in crate)
unsafe trait FromBytes {}

/// Unsafe marker trait for types that are valid to cast as a slice of bytes.
///
/// This is true of primitive types, and recursively for `#[repr(C)]`
/// compositions of such types, **as long as there is no padding** (such as
/// arrays).
///
/// The derive macro takes care of deriving this trait with the necessary
/// compile-time guards.
pub(in crate)
unsafe trait AsBytes {
    fn as_bytes (self: &'_ Self)
        -> &'_ [u8]
    {
        unsafe {
            // # Safety
            //
            //   - contract of the trait
            let num_bytes: usize = ::core::mem::size_of_val(self);
            ::core::slice::from_raw_parts(
                self
                    as *const Self
                    as *const u8
                ,
                num_bytes,
            )
        }
    }

    fn as_bytes_mut (self: &'_ mut Self)
        -> &'_ mut [u8]
    where
        Self : FromBytes,
    {
        unsafe {
            // # Safety
            //
            //   - contract of the trait (to view as a readable slice),
            //
            //   - `FromBytes` added bound makes mutation sound.
            let num_bytes: usize = ::core::mem::size_of_val(self);
            ::core::slice::from_raw_parts_mut(
                self
                    as *mut Self
                    as *mut u8
                ,
                num_bytes,
            )
        }
    }
}

impl_macro! {
    unsafe
    impl FromBytes, for numeric_types!()
}
impl_macro! {
    unsafe
    impl FromBytes, for composite_types!()
}

impl_macro! {
    unsafe
    impl AsBytes, for numeric_types!()
}
impl_macro! {
    unsafe
    impl AsBytes, for composite_types!()
}

macro_rules! AsBytesAndFromBytes {(
    #[repr(C)]
    $(#[$struct_meta:meta])*
    $struct_vis:vis
    struct $StructName:ident {
        $(
            $(#[$field_meta:meta])*
            $field_vis:vis
            $field_name:ident : $field_ty:ty
        ),* $(,)?
    }
) => (
    #[allow(bad_style, dead_code)]
    const $StructName: () = {
        $(
            const_assert!(
                $field_ty :
                    $crate::zerocopy::AsBytes +
                    $crate::zerocopy::FromBytes +
                ,
            );
        )*
        const_assert!(
            ::core::mem::size_of::<$StructName>() ==
            (0 $(+ ::core::mem::size_of::<$field_ty>())*)
        );
    };

    // # Safety
    //
    //   - struct is `#[repr(C)]`,
    //
    //   - `const_assert!`ions check at compile-time that:
    //
    //       - there is no padding
    //
    //       - the inner types are both `AsBytes` and `FromBytes`
    unsafe impl $crate::zerocopy::AsBytes for $StructName {}
    unsafe impl $crate::zerocopy::FromBytes for $StructName {}
)}
