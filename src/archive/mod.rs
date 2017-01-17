//! Implements a simple parser and extractor for a Unix Archive.
//!
//! There are two "common" formats: BSD and SysV
//!
//! This crate currently only implements the SysV version, which essentially postfixes all
//! names in the archive with a / as a sigil for the end of the name, and uses a special symbol
//! index for looking up symbols faster.

use scroll;
use elf::strtab;

#[cfg(feature = "std")]
pub use super::error;

use error::{Result, Error};

use std::io::Read;
use std::usize;
use std::collections::HashMap;
//use std::fmt::{self, Display};

pub const SIZEOF_MAGIC: usize = 8;
/// The magic number of a Unix Archive
pub const MAGIC: &'static [u8; SIZEOF_MAGIC] = b"!<arch>\x0A";

const SIZEOF_FILE_IDENTIFER: usize = 16;

#[derive(Debug, Clone, PartialEq)]
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
// TODO: serialize more values here
pub struct Header {
    /// The identifier, or name for this file/whatever.
    pub identifier: String,
    /// The timestamp for when this file was last modified. Base 10 number
    pub timestamp: [u8; 12],
    /// The file's owner's id. Base 10 string number
    pub owner_id: [u8; 6],
    /// The file's group id. Base 10 string number
    pub group_id: [u8; 6],
    /// The file's permissions mode. Base 8 number number
    pub mode: [u8; 8],
    /// The size of this file. Base 10 string number
    pub size: usize,
    /// The file header's terminator, always `0x60 0x0A`
    pub terminator: [u8; 2],
}

const SIZEOF_FILE_SIZE: usize = 10;
pub const SIZEOF_HEADER: usize = SIZEOF_FILE_IDENTIFER + 12 + 6 + 6 + 8 + SIZEOF_FILE_SIZE + 2;

impl Header {
    pub fn parse<R: scroll::Gread>(buffer: &R, offset: &mut usize) -> Result<Header> {
        let file_identifier = buffer.gread_slice::<str>(offset, SIZEOF_FILE_IDENTIFER)?.to_string();
        let mut file_modification_timestamp = [0u8; 12];
        buffer.gread_inout(offset, &mut file_modification_timestamp)?;
        let mut owner_id = [0u8; 6];
        buffer.gread_inout(offset, &mut owner_id)?;
        let mut group_id = [0u8; 6];
        buffer.gread_inout(offset, &mut group_id)?;
        let mut file_mode = [0u8; 8];
        buffer.gread_inout(offset, &mut file_mode)?;
        let file_size_pos = *offset;
        let file_size_str = buffer.gread_slice::<str>(offset, SIZEOF_FILE_SIZE)?;
        let mut terminator = [0u8; 2];
        buffer.gread_inout(offset, &mut terminator)?;
        let file_size = match usize::from_str_radix(file_size_str.trim_right(), 10) {
            Ok(file_size) => file_size,
            Err(err) => return Err(Error::Malformed(format!("{:?} Bad file_size {:?} at offset 0x{:X}: {:?} {:?} {:?} {:?} {:?} {:?}",
                err, &file_size_str, file_size_pos, file_identifier, file_modification_timestamp, owner_id, group_id,
                file_mode, &file_size_str)).into()),
        };
        Ok(Header {
            identifier: file_identifier,
            timestamp: file_modification_timestamp.clone(),
            owner_id: owner_id.clone(),
            group_id: group_id.clone(),
            mode: file_mode.clone(),
            size: file_size,
            terminator: terminator,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Represents a single entry in the archive
pub struct Member {
    /// The entry header
    header: Header,
    /// File offset from the start of the archive to where the file begins
    pub offset: u64,
}

impl Member {
    /// Tries to parse the header in `R`, as well as the offset in `R.
    /// **NOTE** the Seek will be pointing at the first byte of whatever the file is, skipping padding.
    /// This is because just like members in the archive, the data section is 2-byte aligned.
    pub fn parse<R: scroll::Gread>(buffer: &R, offset: &mut usize) -> Result<Self> {
        let header = Header::parse(buffer, offset)?;
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
    pub fn name(&self) -> &str {
        &self.header.identifier
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
    pub fn parse<R: scroll::Gread>(buffer: &R, size: usize) -> Result<Index> {
        let mut offset = &mut 0;
        let sizeof_table = buffer.gread::<u32>(offset, scroll::BE)? as usize;
        let mut indexes = Vec::with_capacity(sizeof_table);
        for _ in 0..sizeof_table {
            indexes.push(buffer.gread::<u32>(offset, scroll::BE)?);
        }
        let sizeof_strtab = size - ((sizeof_table * 4) + 4);
        let strtab = strtab::Strtab::parse(buffer, *offset, sizeof_strtab, 0x0)?;
        Ok (Index {
            size: sizeof_table,
            symbol_indexes: indexes,
            strtab: strtab.to_vec(), // because i'm lazy
        })
    }
}

/// Member names greater than 16 bytes are indirectly referenced using a `/<idx` schema,
/// where `idx` is an offset into a newline delimited string table directly following the `//` member
/// of the archive.
#[derive(Debug, Default)]
struct NameIndex {
    strtab: strtab::Strtab<'static>
}

impl NameIndex {
    pub fn parse<R: scroll::Gread> (buffer: &R, offset: &mut usize, size: usize) -> Result<Self> {
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
                    return Err(format!("Could not find {:?} in index", name).into())
                }
            },
            Err (_) => {
                return Err(format!("Bad name index: {:?}", name).into())
            }
        }
    }
}

// TODO: add pretty printer fmt::Display with number of members, and names of members, along with
// the values of the index symbols once implemented
#[derive(Debug)]
/// An in-memory representation of a parsed Unix Archive
pub struct Archive {
    // we can chuck this because the symbol index is a better representation, but we keep for
    // debugging
    index: Index,
    extended_names: NameIndex,
    // the array of members, which are indexed by the members hash and symbol index
    member_array: Vec<Member>,
    members: HashMap<String, usize>,
    // symbol -> member
    symbol_index: HashMap<String, usize>
}

impl Archive {
    pub fn parse<R: Read + scroll::Gread>(buffer: &R, size: usize) -> Result<Archive> {
        let mut magic = [0u8; SIZEOF_MAGIC];
        let mut offset = &mut 0usize;
        buffer.gread_inout(offset, &mut magic)?;
        if &magic != MAGIC {
            use scroll::Pread;
            return Err(Error::BadMagic(magic.pread_into(0)?).into());
        }
        let mut member_array = Vec::new();
        let size = size as u64;
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
            if member.name() == INDEX_NAME {
                *offset = member.offset as usize;
                // get the member data (the index in this case)
                let data: &[u8] = buffer.gread_slice(offset, member.size())?;
                // parse it
                index = Index::parse(&data, member.size())?;
                pos = *offset as u64;
            } else if member.name() == NAME_INDEX_NAME {
                *offset = member.offset as usize;
                extended_names = NameIndex::parse(buffer, offset, member.size())?;
                pos = *offset as u64;
            } else {
                // we move the buffer past the file blob
                *offset += member.size();
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

    fn get (&self, member: &str) -> Option<&Member> {
        if let Some(idx) = self.members.get(member) {
            Some(&self.member_array[*idx])
        } else {
            None
        }
    }

    /// Returns a slice of the raw bytes for the given `member` in the scrollable `buffer`
    pub fn extract<'a, R: scroll::Pread> (&self, member: &str, buffer: &'a R) -> Result<&'a [u8]> {
        if let Some(member) = self.get(member) {
            let bytes = buffer.pread_slice(member.offset as usize, member.size())?;
            Ok(bytes)
        } else {
            Err(format!("Cannot extract member {}, not found", member).into())
        }
    }

    pub fn members(&self) -> Vec<&String> {
        self.members.keys().collect()
    }

    /// Returns the member's name which contains the given `symbol`, if it is in the archive
    pub fn member_of_symbol (&self, symbol: &str) -> Option<&str> {
        if let Some(idx) = self.symbol_index.get(symbol) {
            let name = self.member_array[*idx].name();
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

#[no_mangle]
/// Wow. So Meta. Such symbols.
/// Actually just an unmangled, external symbol used for unit testing itself.  Call it.  I dare you.
pub extern fn wow_so_meta_doge_symbol() { println!("wow_so_meta_doge_symbol")}

#[cfg(test)]
mod tests {
    extern crate scroll;
    use super::*;
    use std::path::Path;
    use std::fs::File;
    use super::super::elf;

    #[test]
    fn parse_file_header() {
        let file_header: [u8; SIZEOF_HEADER] = [0x2f, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                                    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                                    0x20, 0x20, 0x30, 0x20, 0x20, 0x20, 0x20,
                                                    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                                    0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x30,
                                                    0x20, 0x20, 0x20, 0x20, 0x20, 0x30, 0x20,
                                                    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x38,
                                                    0x32, 0x34, 0x34, 0x20, 0x20, 0x20, 0x20,
                                                    0x20, 0x20, 0x60, 0x0a];
        let buffer = scroll::Buffer::new(&file_header[..]);
        match Header::parse(&buffer, &mut 0) {
            Err(_) => assert!(false),
            Ok(file_header2) => {
                let file_header = Header { identifier: "/               ".to_owned(),
                    timestamp: [48, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32],
                    owner_id: [48, 32, 32, 32, 32, 32],
                    group_id: [48, 32, 32, 32, 32, 32],
                    mode: [48, 32, 32, 32, 32, 32, 32, 32],
                    size: 8244, terminator:
                    [96, 10] };
                assert_eq!(file_header, file_header2)
            }
        }
    }

    #[test]
    fn parse_archive() {
        let crt1a: Vec<u8> = include!("../../etc/crt1a.rs");
        const START: &'static str = "_start";
        let len = crt1a.len();
        let buffer = scroll::Buffer::new(crt1a);
        match Archive::parse(&buffer, len) {
            Ok(archive) => {
                assert_eq!(archive.member_of_symbol(START), Some("crt1.o"));
                if let Some(member) = archive.get("crt1.o") {
                    assert_eq!(member.offset, 194);
                    assert_eq!(member.size(), 1928)
                } else {
                    println!("could not get crt1.o");
                    assert!(false)
                }
            },
            Err(err) => {println!("could not parse archive: {:?}", err); assert!(false)}
        };
    }

    #[test]
    fn parse_self_wow_so_meta_doge() {
        let path = Path::new("target").join("debug").join("libgoblin.rlib");
        match File::open(path) {
          Ok(fd) => {
              let buffer = scroll::Buffer::try_from(fd).unwrap();
              let size = buffer.len();
              match Archive::parse(&buffer, size) {
                  Ok(archive) => {
                      let mut found = false;
                      for member in archive.members() {
                          if member.starts_with("goblin") && member.ends_with("0.o") {
                              assert_eq!(archive.member_of_symbol("wow_so_meta_doge_symbol"), Some(member.as_str()));
                              match archive.extract(member.as_str(), &buffer) {
                                  Ok(bytes) => {
                                      match elf::Elf::parse::<scroll::Buffer>(&scroll::Buffer::new(bytes)) {
                                          Ok(elf) => {
                                              assert!(elf.entry == 0);
                                              assert!(elf.bias == 0);
                                              found = true;
                                              break;
                                          },
                                          Err(_) => assert!(false)
                                      }
                                  },
                                  Err(_) => assert!(false)
                              }
                          }
                      }
                      if !found {
                          println!("goblin-<hash>.0.o not found");
                          assert!(false)
                      }
                  },
                  Err(err) => {println!("{:?}", err); assert!(false)}
              }
          },
           Err(err) => {println!("{:?}", err); assert!(false)}
        }
    }
}
