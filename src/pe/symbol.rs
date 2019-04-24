use crate::error;
use crate::strtab;
use core::fmt::{self, Debug};
use scroll::{Pread, Pwrite};

/// Size of a single symbol in the COFF Symbol Table.
pub const COFF_SYMBOL_SIZE: usize = 18;

// Values for `Symbol::section_number`.

/// The symbol record is not yet assigned a section. A `value` of zero
/// indicates that a reference to an external symbol is defined elsewhere.
/// A `value` of non-zero is a common symbol with a size that is specified by the `value`.
pub const IMAGE_SYM_UNDEFINED: i16 = 0;
/// The symbol has an absolute (non-relocatable) `value` and is not an address.
pub const IMAGE_SYM_ABSOLUTE: i16 = -1;
/// The symbol provides general type or debugging information but does not
/// correspond to a section.

// Base types for `Symbol::typ`.

/// No type information or unknown base type. Microsoft tools use this setting
pub const IMAGE_SYM_TYPE_NULL: u16 = 0;
/// No valid type; used with void pointers and functions
pub const IMAGE_SYM_TYPE_VOID: u16 = 1;
/// A character (signed byte)
pub const IMAGE_SYM_TYPE_CHAR: u16 = 2;
/// A 2-byte signed integer
pub const IMAGE_SYM_TYPE_SHORT: u16 = 3;
/// A natural integer type (normally 4 bytes in Windows)
pub const IMAGE_SYM_TYPE_INT: u16 = 4;
/// A 4-byte signed integer
pub const IMAGE_SYM_TYPE_LONG: u16 = 5;
/// A 4-byte floating-point number
pub const IMAGE_SYM_TYPE_FLOAT: u16 = 6;
/// An 8-byte floating-point number
pub const IMAGE_SYM_TYPE_DOUBLE: u16 = 7;
/// A structure
pub const IMAGE_SYM_TYPE_STRUCT: u16 = 8;
/// A union
pub const IMAGE_SYM_TYPE_UNION: u16 = 9;
/// An enumerated type
pub const IMAGE_SYM_TYPE_ENUM: u16 = 10;
/// A member of enumeration (a specific value)
pub const IMAGE_SYM_TYPE_MOE: u16 = 11;
/// A byte; unsigned 1-byte integer
pub const IMAGE_SYM_TYPE_BYTE: u16 = 12;
/// A word; unsigned 2-byte integer
pub const IMAGE_SYM_TYPE_WORD: u16 = 13;
/// An unsigned integer of natural size (normally, 4 bytes)
pub const IMAGE_SYM_TYPE_UINT: u16 = 14;
/// An unsigned 4-byte integer
pub const IMAGE_SYM_TYPE_DWORD: u16 = 15;

// Derived types for `Symbol::typ`.

/// No derived type; the symbol is a simple scalar variable.
pub const IMAGE_SYM_DTYPE_NULL: u16 = 0;
/// The symbol is a pointer to base type.
pub const IMAGE_SYM_DTYPE_POINTER: u16 = 1;
/// The symbol is a function that returns a base type.
pub const IMAGE_SYM_DTYPE_FUNCTION: u16 = 2;
/// The symbol is an array of base type.
pub const IMAGE_SYM_DTYPE_ARRAY: u16 = 3;

pub const IMAGE_SYM_TYPE_MASK: u16 = 0xf;
pub const IMAGE_SYM_DTYPE_SHIFT: usize = 4;

// Values for `Symbol::storage_class`.

/// A special symbol that represents the end of function, for debugging purposes.
pub const IMAGE_SYM_CLASS_END_OF_FUNCTION: u8 = 0xff;
/// No assigned storage class.
pub const IMAGE_SYM_CLASS_NULL: u8 = 0;
/// The automatic (stack) variable.
///
/// The `value` field specifies the stack frame offset.
pub const IMAGE_SYM_CLASS_AUTOMATIC: u8 = 1;
/// A value that Microsoft tools use for external symbols.
///
/// The `value` field indicates the size if the section number is
/// `IMAGE_SYM_UNDEFINED` (0).  If the section number is not zero,
/// then the `value` field specifies the offset within the section.
pub const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
/// A static symbol.
///
/// The 'value' field specifies the offset of the symbol within the section.
/// If the `value` field is zero, then the symbol represents a section name.
pub const IMAGE_SYM_CLASS_STATIC: u8 = 3;
/// A register variable.
///
/// The `value` field specifies the register number.
pub const IMAGE_SYM_CLASS_REGISTER: u8 = 4;
/// A symbol that is defined externally.
pub const IMAGE_SYM_CLASS_EXTERNAL_DEF: u8 = 5;
/// A code label that is defined within the module.
///
/// The `value` field specifies the offset of the symbol within the section.
pub const IMAGE_SYM_CLASS_LABEL: u8 = 6;
/// A reference to a code label that is not defined.
pub const IMAGE_SYM_CLASS_UNDEFINED_LABEL: u8 = 7;
/// The structure member.
///
/// The `value` field specifies the n th member.
pub const IMAGE_SYM_CLASS_MEMBER_OF_STRUCT: u8 = 8;
/// A formal argument (parameter) of a function.
///
/// The `value` field specifies the n th argument.
pub const IMAGE_SYM_CLASS_ARGUMENT: u8 = 9;
/// The structure tag-name entry.
pub const IMAGE_SYM_CLASS_STRUCT_TAG: u8 = 10;
/// A union member.
///
/// The `value` field specifies the n th member.
pub const IMAGE_SYM_CLASS_MEMBER_OF_UNION: u8 = 11;
/// The Union tag-name entry.
pub const IMAGE_SYM_CLASS_UNION_TAG: u8 = 12;
/// A Typedef entry.
pub const IMAGE_SYM_CLASS_TYPE_DEFINITION: u8 = 13;
/// A static data declaration.
pub const IMAGE_SYM_CLASS_UNDEFINED_STATIC: u8 = 14;
/// An enumerated type tagname entry.
pub const IMAGE_SYM_CLASS_ENUM_TAG: u8 = 15;
/// A member of an enumeration.
///
/// The `value` field specifies the n th member.
pub const IMAGE_SYM_CLASS_MEMBER_OF_ENUM: u8 = 16;
/// A register parameter.
pub const IMAGE_SYM_CLASS_REGISTER_PARAM: u8 = 17;
/// A bit-field reference.
///
/// The `value` field specifies the n th bit in the bit field.
pub const IMAGE_SYM_CLASS_BIT_FIELD: u8 = 18;
/// A .bb (beginning of block) or .eb (end of block) record.
///
/// The `value` field is the relocatable address of the code location.
pub const IMAGE_SYM_CLASS_BLOCK: u8 = 100;
/// A value that Microsoft tools use for symbol records that define the extent of a function.
///
/// Records may be begin function (.bf ), end function ( .ef ), and lines in function ( .lf ).
/// For .lf records, the `value` field gives the number of source lines in the function.
/// For .ef records, the `value` field gives the size of the function code.
pub const IMAGE_SYM_CLASS_FUNCTION: u8 = 101;
/// An end-of-structure entry.
pub const IMAGE_SYM_CLASS_END_OF_STRUCT: u8 = 102;
/// The source-file symbol record.
///
/// The symbol is followed by auxiliary records that name the file.
pub const IMAGE_SYM_CLASS_FILE: u8 = 103;
/// A definition of a section (Microsoft tools use STATIC storage class instead).
pub const IMAGE_SYM_CLASS_SECTION: u8 = 104;
/// A weak external.
pub const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;
/// A CLR token symbol.
///
/// The name is an ASCII string that consists of the hexadecimal value of the token.
pub const IMAGE_SYM_CLASS_CLR_TOKEN: u8 = 107;

/// A COFF symbol.
///
/// Unwind information for this function can be loaded with [`ExceptionData::get_unwind_info`].
///
/// [`ExceptionData::get_unwind_info`]: struct.ExceptionData.html#method.get_unwind_info
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Default, Pread, Pwrite)]
pub struct Symbol {
    /// The name of the symbol.
    ///
    /// An array of 8 bytes is used if the name is not more than 8 bytes long.
    /// This array is padded with nulls on the right if the name is less than 8 bytes long.
    ///
    /// For longer names, the first 4 bytes are all zeros, and the second 4 bytes
    /// are an offset into the string table.
    pub name: [u8; 8],
    /// The value that is associated with the symbol.
    ///
    /// The interpretation of this field depends on `section_number` and
    /// `storage_class`. A typical meaning is the relocatable address.
    pub value: u32,
    /// A one-based index into the section table. Zero and negative values have special meanings.
    pub section_number: i16,
    /// A number that represents type.
    ///
    /// Microsoft tools set this field to 0x20 (function) or 0x0 (not a function).
    pub typ: u16,
    /// An enumerated value that represents storage class.
    pub storage_class: u8,
    /// The number of auxiliary symbol table entries that follow this record.
    ///
    /// Each auxiliary record is the same size as a standard symbol-table record (18 bytes),
    /// but rather than define a new symbol, the auxiliary record gives additional information
    /// on the last symbol defined.
    pub number_of_aux_symbols: u8,
}

impl Symbol {
    /// Parse the symbol at the given offset.
    ///
    /// If the symbol has an inline name, then also returns a reference to the name's
    /// location in `bytes`.
    pub fn parse<'a>(bytes: &'a [u8], offset: usize) -> error::Result<(Option<&'a str>, Symbol)> {
        let symbol = bytes.pread::<Symbol>(offset)?;
        let name = if symbol.name[0] != 0 {
            bytes[offset..][..8].pread(0).ok()
        } else {
            None
        };
        Ok((name, symbol))
    }

    /// Returns the symbol name.
    ///
    /// This may be a reference to an inline name in the symbol, or to
    /// a strtab entry.
    pub fn name<'a>(&'a self, strtab: &'a strtab::Strtab) -> error::Result<&'a str> {
        if let Some(offset) = self.name_offset() {
            strtab.get(offset as usize).unwrap_or_else(|| {
                Err(error::Error::Malformed(format!(
                    "Invalid Symbol name offset {:#x}",
                    offset
                )))
            })
        } else {
            Ok(self.name.pread(0)?)
        }
    }

    /// Return the strtab offset of the symbol name.
    ///
    /// Returns `None` if the name is inline.
    pub fn name_offset(&self) -> Option<u32> {
        if self.name[0] == 0 {
            self.name.pread_with(4, scroll::LE).ok()
        } else {
            None
        }
    }

    /// Return the base type of the symbol.
    ///
    /// This type uses the `IMAGE_SYM_TYPE_*` definitions.
    pub fn base_type(&self) -> u16 {
        self.typ & IMAGE_SYM_TYPE_MASK
    }

    /// Return the derived type of the symbol.
    ///
    /// This type uses the `IMAGE_SYM_DTYPE_*` definitions.
    pub fn derived_type(&self) -> u16 {
        self.typ >> IMAGE_SYM_DTYPE_SHIFT
    }
}

/// A COFF symbol table.
pub struct SymbolTable<'a> {
    symbols: &'a [u8],
}

impl<'a> SymbolTable<'a> {
    /// Parse a COFF symbol table at the given offset.
    ///
    /// The offset and number of symbols should be from the COFF header.
    pub fn parse(bytes: &'a [u8], offset: usize, number: usize) -> error::Result<SymbolTable<'a>> {
        let symbols = bytes.pread_with(offset, Self::size(number))?;
        Ok(SymbolTable { symbols })
    }

    /// Get the size in bytes of the symbol table.
    pub fn size(number: usize) -> usize {
        number * COFF_SYMBOL_SIZE
    }

    /// Get the symbol at the given index.
    ///
    /// If the symbol has an inline name, then also returns a reference to the name's
    /// location in `bytes`.
    pub fn get(&self, index: usize) -> Option<(Option<&'a str>, Symbol)> {
        let offset = index * COFF_SYMBOL_SIZE;
        Symbol::parse(self.symbols, offset).ok()
    }

    /// Return an iterator for the COFF symbols.
    ///
    /// This iterator skips over auxiliary symbol records.
    pub fn iter(&self) -> SymbolIterator<'a> {
        SymbolIterator {
            index: 0,
            symbols: self.symbols,
        }
    }
}

impl<'a> Debug for SymbolTable<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SymbolTable")
            .field("symbols", &self.iter().collect::<Vec<_>>())
            .finish()
    }
}

/// An iterator for COFF symbols.
///
/// This iterator skips over auxiliary symbol records.
#[derive(Default)]
pub struct SymbolIterator<'a> {
    index: usize,
    symbols: &'a [u8],
}

impl<'a> Iterator for SymbolIterator<'a> {
    type Item = (usize, Option<&'a str>, Symbol);
    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.index * COFF_SYMBOL_SIZE;
        if offset >= self.symbols.len() {
            None
        } else {
            let index = self.index;
            let (name, symbol) = Symbol::parse(self.symbols, offset).ok()?;
            self.index += 1 + symbol.number_of_aux_symbols as usize;
            Some((index, name, symbol))
        }
    }
}
