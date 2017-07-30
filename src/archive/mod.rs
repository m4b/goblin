//! Implements a simple parser and extractor for a Unix Archive.
//!
//! There are two "common" formats: BSD and SysV
//!
//! This crate currently only implements the SysV version, which essentially postfixes all
//! names in the archive with a / as a sigil for the end of the name, and uses a special symbol
//! index for looking up symbols faster.

use scroll::{self, Pread};

use strtab;
use error::{Result, Error};

use std::usize;
use std::collections::HashMap;

pub const SIZEOF_MAGIC: usize = 8;
/// The magic number of a Unix Archive
pub const MAGIC: &'static [u8; SIZEOF_MAGIC] = b"!<arch>\x0A";

const SIZEOF_FILE_IDENTIFER: usize = 16;
const SIZEOF_FILE_SIZE: usize = 10;

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Pread, Pwrite, SizeWith)]
/// A Unix Archive Header - meta data for the file/byte blob/whatever that follows exactly after.
/// All data is right-padded with spaces ASCII `0x20`. The Binary layout is as follows:
///
/// |Offset|Length|Name                       |Format     |
/// |:-----|:-----|:--------------------------|:----------|
/// |0     |16    |File identifier            |ASCII      |
/// |16    |12    |File modification timestamp|Decimal    |
/// |28    |6     |Owner ID                   |Decimal    |
/// |34    |6     |Group ID                   |Decimal    |
/// |40    |8     |File mode                  |Octal      |
/// |48    |10    |Filesize in bytes          |Decimal    |
/// |58    |2     |Ending characters          |`0x60 0x0A`|
///
/// Byte alignment is according to the following:
/// > Each archive file member begins on an even byte boundary; a newline is inserted between files
/// > if necessary. Nevertheless, the size given reflects the actual size of the file exclusive
/// > of padding.
pub struct MemberHeader {
    /// The identifier, or name for this file/whatever.
    pub identifier: [u8; 16],
    /// The timestamp for when this file was last modified. Base 10 number
    pub timestamp: [u8; 12],
    /// The file's owner's id. Base 10 string number
    pub owner_id: [u8; 6],
    /// The file's group id. Base 10 string number
    pub group_id: [u8; 6],
    /// The file's permissions mode. Base 8 number number
    pub mode: [u8; 8],
    /// The size of this file. Base 10 string number
    pub file_size: [u8; 10],
    /// The file header's terminator, always `0x60 0x0A`
    pub terminator: [u8; 2],
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Header<'a> {
    pub name: &'a str,
    pub size: usize,
}

pub const SIZEOF_HEADER: usize = SIZEOF_FILE_IDENTIFER + 12 + 6 + 6 + 8 + SIZEOF_FILE_SIZE + 2;

impl MemberHeader {
    pub fn name(&self) -> Result<&str> {
        Ok(self.identifier.pread_with::<&str>(0, ::scroll::ctx::StrCtx::Length(SIZEOF_FILE_IDENTIFER))?)
    }
    pub fn size(&self) -> Result<usize> {
        match usize::from_str_radix(self.file_size.pread_with::<&str>(0, ::scroll::ctx::StrCtx::Length(self.file_size.len()))?.trim_right(), 10) {
            Ok(file_size) => Ok(file_size),
            Err(err) => Err(Error::Malformed(format!("{:?} Bad file_size in header: {:?}", err, self)))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Represents a single entry in the archive
pub struct Member<'a> {
    /// The entry header
    pub header: Header<'a>,
    /// File offset from the start of the archive to where the file begins
    pub offset: u64,
}

impl<'a> Member<'a> {
    /// Tries to parse the header in `R`, as well as the offset in `R.
    /// **NOTE** the Seek will be pointing at the first byte of whatever the file is, skipping padding.
    /// This is because just like members in the archive, the data section is 2-byte aligned.
    pub fn parse(buffer: &'a [u8], offset: &mut usize) -> Result<Member<'a>> {
        let name = buffer.pread_with::<&str>(*offset, ::scroll::ctx::StrCtx::Length(SIZEOF_FILE_IDENTIFER))?;
        let archive_header = buffer.gread::<MemberHeader>(offset)?;
        let header = Header { name: name, size: archive_header.size()? };
        // skip newline padding if we're on an uneven byte boundary
        if *offset & 1 == 1 {
            *offset += 1;
        }
        Ok(Member {
            header: header,
            offset: *offset as u64,
        })
    }

    /// The size of the Member's content, in bytes. Does **not** include newline padding,
    /// nor the size of the file header.
    pub fn size(&self) -> usize {
        self.header.size
    }

    fn trim(name: &str) -> &str {
        name.trim_right_matches(' ').trim_right_matches('/')
    }

    /// The untrimmed raw member name, i.e., includes right-aligned space padding and `'/'` end-of-string
    /// identifier
    pub fn name(&self) -> &'a str {
        self.header.name
    }

}

#[derive(Debug, Default)]
/// The special index member signified by the name `'/'`.
/// The data element contains a list of symbol indexes and symbol names, giving their offsets
/// into the archive for a given name.
pub struct Index {
    /// Big Endian number of symbol_indexes and strings
    pub size: usize,
    /// Big Endian u32 index into the archive for this symbol (index in array is the index into the string table)
    pub symbol_indexes: Vec<u32>,
    /// Set of zero-terminated strings indexed by above. Number of strings = `self.size`
    pub strtab: Vec<String>,
}

/// SysV Archive Variant Symbol Lookup Table "Magic" Name
const INDEX_NAME: &'static str = "/               ";
/// SysV Archive Variant Extended Filename String Table Name
const NAME_INDEX_NAME: &'static str = "//              ";

impl Index {
    /// Parses the given byte buffer into an Index. NB: the buffer must be the start of the index
    pub fn parse(buffer: &[u8], size: usize) -> Result<Index> {
        let mut offset = &mut 0;
        let sizeof_table = buffer.gread_with::<u32>(offset, scroll::BE)? as usize;
        let mut indexes = Vec::with_capacity(sizeof_table);
        for _ in 0..sizeof_table {
            indexes.push(buffer.gread_with::<u32>(offset, scroll::BE)?);
        }
        let sizeof_strtab = size - ((sizeof_table * 4) + 4);
        let strtab = strtab::Strtab::parse(buffer, *offset, sizeof_strtab, 0x0)?;
        Ok (Index {
            size: sizeof_table,
            symbol_indexes: indexes,
            strtab: strtab.to_vec()?, // because i'm lazy
        })
    }
}

/// Member names greater than 16 bytes are indirectly referenced using a `/<idx` schema,
/// where `idx` is an offset into a newline delimited string table directly following the `//` member
/// of the archive.
#[derive(Debug, Default)]
struct NameIndex<'a> {
    strtab: strtab::Strtab<'a>
}

impl<'a> NameIndex<'a> {
    pub fn parse(buffer: &'a [u8], offset: &mut usize, size: usize) -> Result<NameIndex<'a>> {
        // This is a total hack, because strtab returns "" if idx == 0, need to change
        // but previous behavior might rely on this, as ELF strtab's have "" at 0th index...
        let hacked_size = size + 1;
        let strtab = strtab::Strtab::parse(buffer, *offset-1, hacked_size, '\n' as u8)?;
        // precious time was lost when refactoring because strtab::parse doesn't update the mutable seek...
        *offset += hacked_size - 2;
        Ok (NameIndex {
            strtab: strtab
        })
    }

    pub fn get(&self, name: &str) -> Result<&str> {
        let idx = name.trim_left_matches('/').trim_right();
        match usize::from_str_radix(idx, 10) {
            Ok(idx) => {
                let name = &self.strtab[idx+1];
                if name != "" {
                    Ok(name.trim_right_matches('/'))
                }  else {
                    return Err(Error::Malformed(format!("Could not find {:?} in index", name).into()));
                }
            },
            Err (_) => {
                return Err(Error::Malformed(format!("Bad name index {:?} in index", name).into()));
            }
        }
    }
}

// TODO: add pretty printer fmt::Display with number of members, and names of members, along with
// the values of the index symbols once implemented
#[derive(Debug)]
/// An in-memory representation of a parsed Unix Archive
pub struct Archive<'a> {
    // we can chuck this because the symbol index is a better representation, but we keep for
    // debugging
    index: Index,
    extended_names: NameIndex<'a>,
    // the array of members, which are indexed by the members hash and symbol index
    member_array: Vec<Member<'a>>,
    members: HashMap<String, usize>,
    // symbol -> member
    symbol_index: HashMap<String, usize>
}

impl<'a> Archive<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Archive<'a>> {
        let mut magic = [0u8; SIZEOF_MAGIC];
        let mut offset = &mut 0usize;
        buffer.gread_inout(offset, &mut magic)?;
        if &magic != MAGIC {
            use scroll::Pread;
            return Err(Error::BadMagic(magic.pread(0)?).into());
        }
        let mut member_array = Vec::new();
        let size = buffer.as_ref().len() as u64;
        let mut pos = 0u64;
        let mut index = Index::default();
        let mut extended_names = NameIndex::default();
        loop {
            if pos >= size { break }
            // if the member is on an uneven byte boundary, we bump the buffer
            if pos & 1 == 1 {
                *offset += 1;
            }
            let member = Member::parse(buffer, offset)?;
            let name = member.name();
            let size = member.size();
            if name == INDEX_NAME {
                *offset = member.offset as usize;
                // get the member data (the index in this case)
                // FIXME, TODO: gread_slice needs to return
                //let data: &[u8] = buffer.gread_slice(offset, size)?;
                let data: &[u8] = &buffer[*offset..];
                *offset += size;
                // parse it
                index = Index::parse(&data, size)?;
                pos = *offset as u64;
            } else if name == NAME_INDEX_NAME {
                *offset = member.offset as usize;
                extended_names = NameIndex::parse(buffer, offset, size)?;
                pos = *offset as u64;
            } else {
                // we move the buffer past the file blob
                *offset += size;
                pos = *offset as u64;
                member_array.push(member);
            }
        }

        // this preprocesses the member names so they are searchable by their canonical versions
        let mut members = HashMap::new();
        for (i, member) in member_array.iter().enumerate() {
            let key = {
                let name = member.name();
                if name.starts_with("/") {
                    try!(extended_names.get(name))
                } else {
                    Member::trim(name)
            }}.to_owned();
            members.insert(key, i);
        }

        let mut symbol_index = HashMap::new();
        let mut last_symidx = 0u32;
        let mut last_member = 0usize;
        for (i, symidx) in index.symbol_indexes.iter().enumerate() {
            let name = index.strtab[i].to_owned();
            if *symidx == last_symidx {
                symbol_index.insert(name, last_member);
            } else {
                for (memidx, member) in member_array.iter().enumerate() {
                    if *symidx == (member.offset - SIZEOF_HEADER as u64) as u32 {
                        symbol_index.insert(name, memidx);
                        last_symidx = *symidx;
                        last_member = memidx;
                        break
                    }
                }
            }
        }

        let archive = Archive {
            index: index,
            member_array: member_array,
            extended_names: extended_names,
            members: members,
            symbol_index: symbol_index,
        };
        Ok(archive)
    }

    pub fn get (&self, member: &str) -> Option<&Member> {
        if let Some(idx) = self.members.get(member) {
            Some(&self.member_array[*idx])
        } else {
            None
        }
    }

    /// Returns a slice of the raw bytes for the given `member` in the scrollable `buffer`
    pub fn extract<'b>(&self, member: &str, buffer: &'b [u8]) -> Result<&'b [u8]> {
        if let Some(member) = self.get(member) {
            let bytes = buffer.pread_with(member.offset as usize, member.size())?;
            Ok(bytes)
        } else {
            Err(Error::Malformed(format!("Cannot extract member {:?}", member).into()))
        }
    }

    pub fn members(&self) -> Vec<&String> {
        self.members.keys().collect()
    }

    /// Returns the member's name which contains the given `symbol`, if it is in the archive
    pub fn member_of_symbol (&self, symbol: &str) -> Option<&str> {
        if let Some(idx) = self.symbol_index.get(symbol) {
            let name = (self.member_array[*idx]).name();
            if name.starts_with("/") {
                Some(self.extended_names.get(name).unwrap())
            } else {
                Some(Member::trim(name))
            }
        } else {
            None
        }
    }
}
