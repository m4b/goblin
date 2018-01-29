/// === Sym bindings ===
/// Local symbol.
pub const STB_LOCAL: u8 = 0;
/// Global symbol.
pub const STB_GLOBAL: u8 = 1;
/// Weak symbol.
pub const STB_WEAK: u8 = 2;
/// Number of defined types..
pub const STB_NUM: u8 = 3;
/// Start of OS-specific.
pub const STB_LOOS: u8 = 10;
/// Unique symbol..
pub const STB_GNU_UNIQUE: u8 = 10;
/// End of OS-specific.
pub const STB_HIOS: u8 = 12;
/// Start of processor-specific.
pub const STB_LOPROC: u8 = 13;
/// End of processor-specific.
pub const STB_HIPROC: u8 = 15;

/// === Sym types ===
/// Symbol type is unspecified.
pub const STT_NOTYPE: u8 = 0;
/// Symbol is a data object.
pub const STT_OBJECT: u8 = 1;
/// Symbol is a code object.
pub const STT_FUNC: u8 = 2;
/// Symbol associated with a section.
pub const STT_SECTION: u8 = 3;
/// Symbol's name is file name.
pub const STT_FILE: u8 = 4;
/// Symbol is a common data object.
pub const STT_COMMON: u8 = 5;
/// Symbol is thread-local data object.
pub const STT_TLS: u8 = 6;
/// Number of defined types.
pub const STT_NUM: u8 = 7;
/// Start of OS-specific.
pub const STT_LOOS: u8 = 10;
/// Symbol is indirect code object.
pub const STT_GNU_IFUNC: u8 = 10;
/// End of OS-specific.
pub const STT_HIOS: u8 = 12;
/// Start of processor-specific.
pub const STT_LOPROC: u8 = 13;
/// End of processor-specific.
pub const STT_HIPROC: u8 = 15;

/// Get the ST bind.
///
/// This is the first four bits of the byte.
#[inline]
pub fn st_bind(info: u8) -> u8 {
    info >> 4
}

/// Get the ST type.
///
/// This is the last four bits of the byte.
#[inline]
pub fn st_type(info: u8) -> u8 {
    info & 0xf
}

/// Is this information defining an import?
#[inline]
pub fn is_import(info: u8, value: u64) -> bool {
    let bind = st_bind(info);
    bind == STB_GLOBAL && value == 0
}

/// Convenience function to get the &'static str type from the symbols `st_info`.
pub fn get_type(info: u8) -> &'static str {
    type_to_str(st_type(info))
}

/// Get the string for some bind.
#[inline]
pub fn bind_to_str(typ: u8) -> &'static str {
    match typ {
        STB_LOCAL => "LOCAL",
        STB_GLOBAL => "GLOBAL",
        STB_WEAK => "WEAK",
        STB_NUM => "NUM",
        STB_GNU_UNIQUE => "GNU_UNIQUE",
        _ => "UNKNOWN_STB",
    }
}

/// Get the string for some type.
#[inline]
pub fn type_to_str(typ: u8) -> &'static str {
    match typ {
        STT_NOTYPE => "NOTYPE",
        STT_OBJECT => "OBJECT",
        STT_FUNC => "FUNC",
        STT_SECTION => "SECTION",
        STT_FILE => "FILE",
        STT_COMMON => "COMMON",
        STT_TLS => "TLS",
        STT_NUM => "NUM",
        STT_GNU_IFUNC => "GNU_IFUNC",
        _ => "UNKNOWN_STT",
    }
}

macro_rules! elf_sym_std_impl {
    ($size:ty) => {

        #[cfg(test)]
        mod test {
            use super::*;
            #[test]
            fn size_of() {
                assert_eq!(::std::mem::size_of::<Sym>(), SIZEOF_SYM);
            }
        }

        if_std! {
            use elf::sym::Sym as ElfSym;
            use error::Result;

            use core::fmt;
            use core::slice;

            use std::fs::File;
            use std::io::{Read, Seek};
            use std::io::SeekFrom::Start;

            impl Sym {
                /// Checks whether this `Sym` has `STB_GLOBAL`/`STB_WEAK` bind and a `st_value` of 0
                pub fn is_import(&self) -> bool {
                    let bind = self.st_info >> 4;
                    (bind == STB_GLOBAL || bind == STB_WEAK) && self.st_value == 0
                }
                /// Checks whether this `Sym` has type `STT_FUNC`
                pub fn is_function(&self) -> bool {
                    st_type(self.st_info) == STT_FUNC
                }
            }

            impl From<Sym> for ElfSym {
                fn from(sym: Sym) -> Self {
                    ElfSym {
                        st_name:     sym.st_name as usize,
                        st_info:     sym.st_info,
                        st_other:    sym.st_other,
                        st_shndx:    sym.st_shndx as usize,
                        st_value:    sym.st_value as u64,
                        st_size:     sym.st_size as u64,
                    }
                }
            }

            impl From<ElfSym> for Sym {
                fn from(sym: ElfSym) -> Self {
                    Sym {
                        st_name:     sym.st_name as u32,
                        st_info:     sym.st_info,
                        st_other:    sym.st_other,
                        st_shndx:    sym.st_shndx as u16,
                        st_value:    sym.st_value as $size,
                        st_size:     sym.st_size as $size,
                    }
                }
            }

            impl fmt::Debug for Sym {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    let bind = st_bind(self.st_info);
                    let typ = st_type(self.st_info);
                    write!(f,
                           "st_name: {} {} {} st_other: {} st_shndx: {} st_value: {:x} st_size: {}",
                           self.st_name,
                           bind_to_str(bind),
                           type_to_str(typ),
                           self.st_other,
                           self.st_shndx,
                           self.st_value,
                           self.st_size)
                }
            }

            pub unsafe fn from_raw<'a>(symp: *const Sym, count: usize) -> &'a [Sym] {
                slice::from_raw_parts(symp, count)
            }

            pub fn from_fd(fd: &mut File, offset: usize, count: usize) -> Result<Vec<Sym>> {
                // TODO: AFAIK this shouldn't work, since i pass in a byte size...
                let mut syms = vec![Sym::default(); count];
                try!(fd.seek(Start(offset as u64)));
                unsafe {
                    try!(fd.read(plain::as_mut_bytes(&mut *syms)));
                }
                syms.dedup();
                Ok(syms)
            }
        } // end if_std
    };
}

pub mod sym32 {
    pub use elf::sym::*;

    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Default)]
    #[cfg_attr(feature = "std", derive(Pread, Pwrite, SizeWith))]
    /// 32-bit Sym - used for both static and dynamic symbol information in a binary
    pub struct Sym {
        /// Symbol name (string tbl index)
        pub st_name: u32,
        /// Symbol value
        pub st_value: u32,
        /// Symbol size
        pub st_size: u32,
        /// Symbol type and binding
        pub st_info: u8,
        /// Symbol visibility
        pub st_other: u8,
        /// Section index
        pub st_shndx: u16,
    }

    use plain;
    // Declare that the type is plain.
    unsafe impl plain::Plain for Sym {}

    pub const SIZEOF_SYM: usize = 4 + 1 + 1 + 2 + 4 + 4;

    elf_sym_std_impl!(u32);
}

pub mod sym64 {
    pub use elf::sym::*;

    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Default)]
    #[cfg_attr(feature = "std", derive(Pread, Pwrite, SizeWith))]
    /// 64-bit Sym - used for both static and dynamic symbol information in a binary
    pub struct Sym {
        /// Symbol name (string tbl index)
        pub st_name: u32,
        /// Symbol type and binding
        pub st_info: u8,
        /// Symbol visibility
        pub st_other: u8,
        /// Section index
        pub st_shndx: u16,
        /// Symbol value
        pub st_value: u64,
        /// Symbol size
        pub st_size: u64,
    }

    use plain;
    // Declare that the type is plain.
    unsafe impl plain::Plain for Sym {}

    pub const SIZEOF_SYM: usize = 4 + 1 + 1 + 2 + 8 + 8;

    elf_sym_std_impl!(u64);
}

if_std! {
    use lazy_transducer::{ScrollTransducer, IntoIter, IntoParIter};
    use rayon::prelude::*;
    use scroll::{ctx, Pread};
    use scroll::ctx::SizeWith;
    use core::fmt::{self, Debug};
    use core::result;
    use container::{Ctx, Container};
    use error::Result;

    #[derive(Default, PartialEq, Clone)]
    /// A unified Sym definition - convertable to and from 32-bit and 64-bit variants
    pub struct Sym {
        pub st_name:     usize,
        pub st_info:     u8,
        pub st_other:    u8,
        pub st_shndx:    usize,
        pub st_value:    u64,
        pub st_size:     u64,
    }

    impl Sym {
        pub fn size(container: Container) -> usize {
            use scroll::ctx::SizeWith;
            Self::size_with(&Ctx::from(container))
        }
        /// Checks whether this `Sym` has `STB_GLOBAL`/`STB_WEAK` bind and a `st_value` of 0
        pub fn is_import(&self) -> bool {
            let bind = self.st_bind();
            (bind == STB_GLOBAL || bind == STB_WEAK) && self.st_value == 0
        }
        /// Checks whether this `Sym` has type `STT_FUNC`
        pub fn is_function(&self) -> bool {
            st_type(self.st_info) == STT_FUNC
        }
        /// Get the ST bind.
        ///
        /// This is the first four bits of the byte.
        #[inline]
        pub fn st_bind(&self) -> u8 {
            self.st_info >> 4
        }
        /// Get the ST type.
        ///
        /// This is the last four bits of the byte.
        #[inline]
        pub fn st_type(&self) -> u8 {
            self.st_info & 0xf
        }
        #[cfg(feature = "endian_fd")]
        /// Parse `count` vector of ELF symbols from `offset`
        pub fn parse(bytes: &[u8], mut offset: usize, count: usize, ctx: Ctx) -> Result<Vec<Sym>> {
            use scroll::Pread;
            let mut syms = Vec::with_capacity(count);
            for _ in 0..count {
                let sym = bytes.gread_with(&mut offset, ctx)?;
                syms.push(sym);
            }
            Ok(syms)
        }
    }

    impl fmt::Debug for Sym {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let bind = self.st_bind();
            let typ = self.st_type();
            write!(f,
                   "st_name: {} {} {} st_other: {} st_shndx: {} st_value: {:x} st_size: {}",
                   self.st_name,
                   bind_to_str(bind),
                   type_to_str(typ),
                   self.st_other,
                   self.st_shndx,
                   self.st_value,
                   self.st_size)
        }
    }

    impl ctx::SizeWith<Ctx> for Sym {
        type Units = usize;
        fn size_with(&Ctx {container, .. }: &Ctx) -> usize {
            match container {
                Container::Little => {
                    sym32::SIZEOF_SYM
                },
                Container::Big => {
                    sym64::SIZEOF_SYM
                },
            }
        }
    }

    impl<'a> ctx::TryFromCtx<'a, Ctx> for Sym {
        type Error = ::error::Error;
        type Size = usize;
        fn try_from_ctx(bytes: &'a [u8], Ctx { container, le}: Ctx) -> result::Result<(Self, Self::Size), Self::Error> {
            use scroll::Pread;
            let sym = match container {
                Container::Little => {
                    (bytes.pread_with::<sym32::Sym>(0, le)?.into(), sym32::SIZEOF_SYM)
                },
                Container::Big => {
                    (bytes.pread_with::<sym64::Sym>(0, le)?.into(), sym64::SIZEOF_SYM)
                }
            };
            Ok(sym)
        }
    }

    impl ctx::TryIntoCtx<Ctx> for Sym {
        type Error = ::error::Error;
        type Size = usize;
        fn try_into_ctx(self, bytes: &mut [u8], Ctx {container, le}: Ctx) -> result::Result<Self::Size, Self::Error> {
            use scroll::Pwrite;
            match container {
                Container::Little => {
                    let sym: sym32::Sym = self.into();
                    Ok(bytes.pwrite_with(sym, 0, le)?)
                },
                Container::Big => {
                    let sym: sym64::Sym = self.into();
                    Ok(bytes.pwrite_with(sym, 0, le)?)
                }
            }
        }
    }

    impl ctx::IntoCtx<Ctx> for Sym {
        fn into_ctx(self, bytes: &mut [u8], Ctx {container, le}: Ctx) {
            use scroll::Pwrite;
            match container {
                Container::Little => {
                    let sym: sym32::Sym = self.into();
                    bytes.pwrite_with(sym, 0, le).unwrap();
                },
                Container::Big => {
                    let sym: sym64::Sym = self.into();
                    bytes.pwrite_with(sym, 0, le).unwrap();
                }
            }
        }
    }

    /// An ELF symbol table, allowing lazy iteration over symbols
    pub struct Symtab<'a> {
        bytes: &'a [u8],
        start: usize,
        end: usize,
        lt: ScrollTransducer<'a, Sym, Ctx>,
    }

    impl<'a> Default for Symtab<'a> {
        fn default() -> Self {
            let bytes = &[];
            Symtab {
                bytes,
                start: 0,
                end: 0,
                lt: ScrollTransducer::parse_with(bytes, 0, Ctx::default()).unwrap(),
            }
        }
    }

    impl<'a> Debug for Symtab<'a> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            let len = self.bytes.len();
            fmt.debug_struct("Symtab")
                .field("bytes", &len)
                .field("range", &format!("{:#x}..{:#x}", self.start, self.end))
                .field("count", &self.lt.len())
                .field("Symbols", &self.to_vec())
                .finish()
        }
    }

    pub type SymIter<'a> = IntoIter<'a, (&'a [u8], Ctx), Sym>;
    pub type SymParIter<'a> = IntoParIter<'a, (&'a [u8], Ctx), Sym>;

    impl<'a> Symtab<'a> {
        /// Parse a table of `count` ELF symbols from `offset`.
        pub fn parse(bytes: &'a [u8], offset: usize, count: usize, ctx: Ctx) -> Result<Symtab<'a>> {
            // scrolltransducer does all this for us, but i don't feel like re-mapping the error
            let size = count * Sym::size_with(&ctx);
            // TODO: make this a better error message when too large
            let bytes = bytes.pread_with(offset, size)?;
            let lt = ScrollTransducer::parse_with(bytes, count, ctx).unwrap();
            Ok(Symtab { bytes, start: offset, end: offset+size, lt })
        }

        /// Try to parse a single symbol from the binary, at `index`.
        pub fn get(&self, index: usize) -> Option<Sym> {
            self.lt.get(index)
        }

        /// The number of symbols in the table.
        #[inline]
        pub fn len(&self) -> usize {
            self.lt.len()
        }

        /// Iterate over all symbols.
        pub fn iter(&self) -> SymIter<'a> {
            self.into_iter()
        }

        /// Iterate over all symbols in parallel
        pub fn par_iter(&self) -> SymParIter<'a> {
            self.lt.clone().into_par_iter()
        }

        /// Parse all symbols into a vector.
        pub fn to_vec(&self) -> Vec<Sym> {
            self.lt.clone().into_par_iter().collect()
        }
    }

    impl<'a, 'b> IntoIterator for &'b Symtab<'a> {
        //type Item = <SymIterator<'a> as Iterator>::Item;
        type Item = <SymIter<'a> as Iterator>::Item;
        type IntoIter = SymIter<'a>;

        fn into_iter(self) -> Self::IntoIter {
            self.lt.clone().into_iter()
        }
    }

    // impl<'a, 'b> IntoIterator for &'b Symtab<'a> {
    //     type Item = <SymIterator<'a> as Iterator>::Item;
    //     type IntoIter = SymIterator<'a>;

    //     fn into_iter(self) -> Self::IntoIter {
    //         SymIterator {
    //             bytes: self.bytes,
    //             offset: 0,
    //             index: 0,
    //             count: self.count,
    //             ctx: self.ctx,
    //         }
    //     }
    // }

    /// An iterator over symbols in an ELF symbol table
    pub struct SymIterator<'a> {
        bytes: &'a [u8],
        offset: usize,
        index: usize,
        count: usize,
        ctx: Ctx,
    }

    impl<'a> Iterator for SymIterator<'a> {
        type Item = Sym;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index >= self.count {
                None
            } else {
                self.index += 1;
                Some(self.bytes.gread_with(&mut self.offset, self.ctx).unwrap())
            }
        }
    }

    impl<'a> ExactSizeIterator for SymIterator<'a> {
        fn len(&self) -> usize {
            self.count - self.index
        }
    }
} // end if_std
