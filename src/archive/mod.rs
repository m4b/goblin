//! Implements a simple parser and extractor for a Unix Archive.
//!
//! There are two "common" formats: BSD and SysV
//!
//! This crate currently only implements the SysV version, which essentially postfixes all
//! names in the archive with a / as a sigil for the end of the name, and uses a special symbol
//! index for looking up symbols faster.

use byteorder::{BigEndian, ReadBytesExt};

use elf::strtab;

use std::io::{self, Read, Seek, Cursor};
use std::io::SeekFrom::{Start, Current};
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
    pub fn parse<R: Read + Seek>(cursor: &mut R) -> io::Result<Header> {
        let mut file_identifier = vec![0u8; SIZEOF_FILE_IDENTIFER];
        try!(cursor.read_exact(&mut file_identifier));
        let file_identifier = unsafe { String::from_utf8_unchecked(file_identifier) };
        let mut file_modification_timestamp = [0u8; 12];
        try!(cursor.read(&mut file_modification_timestamp));
        let mut owner_id = [0u8; 6];
        try!(cursor.read(&mut owner_id));
        let mut group_id = [0u8; 6];
        try!(cursor.read(&mut group_id));
        let mut file_mode = [0u8; 8];
        try!(cursor.read(&mut file_mode));
        let mut file_size = [0u8; SIZEOF_FILE_SIZE];
        let file_size_pos = try!(cursor.seek(Current(0)));
        try!(cursor.read(&mut file_size));
        let mut terminator = [0u8; 2];
        try!(cursor.read(&mut terminator));
        let string = unsafe { ::std::str::from_utf8_unchecked(&file_size) };
        let file_size = match usize::from_str_radix(string.trim_right(), 10) {
            Ok(file_size) => file_size,
            Err(err) => return io_error!("Err: {:?} Bad file_size {:?} at offset 0x{:X}: {:?} {:?} {:?} {:?} {:?} {:?}",
                err, &file_size, file_size_pos, file_identifier, file_modification_timestamp, owner_id, group_id,
                file_mode, file_size),
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
    pub fn parse<R: Read + Seek>(cursor: &mut R) -> io::Result<Self> {
        let header = try!(Header::parse(cursor));
        let mut offset = try!(cursor.seek(Current(0)));
        // skip newline padding if we're on an uneven byte boundary
        if offset & 1 == 1 {
            offset = try!(cursor.seek(Current(1)));
        }
        Ok(Member {
            header: header,
            offset: offset,
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
    pub fn parse<'c, R: Read + Seek>(cursor: &'c mut R, size: usize) -> io::Result<Index> {
        let sizeof_table = try!(cursor.read_u32::<BigEndian>()) as usize;
        let mut indexes = Vec::with_capacity(sizeof_table);
        for _ in 0..sizeof_table {
            indexes.push(try!(cursor.read_u32::<BigEndian>()));
        }
        let sizeof_strtab = size - ((sizeof_table * 4) + 4);
        let offset = try!(cursor.seek(Current(0)));
        let strtab = try!(strtab::Strtab::parse(cursor, offset as usize, sizeof_strtab, 0x0));
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
    pub fn parse<R: Read + Seek> (cursor: &mut R, offset: usize, size: usize) -> io::Result<Self> {
        // This is a total hack, because strtab returns "" if idx == 0, need to change
        // but previous behavior might rely on this, as ELF strtab's have "" at 0th index...
        let strtab = try!(strtab::Strtab::parse(cursor, offset-1, size+1, '\n' as u8));
        Ok (NameIndex {
            strtab: strtab
        })
    }

    pub fn get(&self, name: &str) -> io::Result<&str> {
        let idx = name.trim_left_matches('/').trim_right();
        match usize::from_str_radix(idx, 10) {
            Ok(idx) => {
                let name = &self.strtab[idx+1];
                if name != "" {
                    Ok(name.trim_right_matches('/'))
                }  else {
                    return io_error!(format!("Could not find {:?} in index", name))
                }
            },
            Err (_) => {
                return io_error!(format!("Bad name index: {:?}", name))
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
    pub fn parse<R: Read + Seek>(mut cursor: &mut R, size: usize) -> io::Result<Archive> {
        try!(cursor.seek(Start(0)));
        let mut magic = [0; SIZEOF_MAGIC];
        try!(cursor.read_exact(&mut magic));
        if &magic != MAGIC {
            return io_error!("Invalid Archive magic number: {:?}", &magic);
        }
        let mut member_array = Vec::new();
        let size = size as u64;
        let mut pos = 0u64;
        let mut index = Index::default();
        let mut extended_names = NameIndex::default();
        loop {
            if pos >= size { break }
            // if the member is on an uneven byte boundary, we bump the cursor
            if pos & 1 == 1 {
                try!(cursor.seek(Current(1)));
            }
            let member = try!(Member::parse(&mut cursor));
            if member.name() == INDEX_NAME {
                let mut data = vec![0u8; member.size()];
                try!(cursor.seek(Start(member.offset)));
                try!(cursor.read_exact(&mut data));
                let mut data = Cursor::new(&data);
                index = try!(Index::parse(&mut data, member.size()));
                pos = try!(cursor.seek(Current(0)));
            } else if member.name() == NAME_INDEX_NAME {
                extended_names = try!(NameIndex::parse(cursor, member.offset as usize, member.size()));
                pos = try!(cursor.seek(Current(0)));
            } else {
                // we move the cursor past the file blob
                pos = try!(cursor.seek(Current(member.size() as i64)));
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

    /// Returns a vector of the raw bytes for the given `member` in the readable `cursor`
    pub fn extract<R: Read + Seek> (&self, member: &str, cursor: &mut R) -> io::Result<Vec<u8>> {
        if let Some(member) = self.get(member) {
            let mut bytes = vec![0u8; member.size()];
            try!(cursor.seek(Start(member.offset)));
            try!(cursor.read_exact(&mut bytes));
            Ok(bytes)
        } else {
            io_error!(format!("Cannot extract member {}, not found", member))
        }
    }

    /// Returns the member's name which contains the given `symbol`, if it is in the archive
    pub fn member_of_symbol (&self, symbol: &str) -> Option<&str> {
        if let Some(idx) = self.symbol_index.get(symbol) {
            Some (Member::trim(self.member_array[*idx].name()))
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
    use super::*;
    use std::io::Cursor;
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
        let mut cursor = Cursor::new(&file_header[..]);
        match Header::parse(&mut cursor) {
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
        let mut cursor = Cursor::new(&crt1a);
        match Archive::parse(&mut cursor, crt1a.len()) {
            Ok(archive) => {
                assert_eq!(archive.member_of_symbol(START), Some("crt1.o"));
                if let Some(member) = archive.get("crt1.o") {
                    assert_eq!(member.offset, 194);
                    assert_eq!(member.size(), 1928)
                } else {
                    assert!(false)
                }
            },
            Err(_) => assert!(false),
        };
    }

    #[test]
    fn parse_self_wow_so_meta_doge() {
        const GOBLIN: &'static str = "goblin.0.o";
        let path = Path::new("target").join("debug").join("libgoblin.rlib");
        match File::open(path) {
          Ok(mut fd) => {
              let size = fd.metadata().unwrap().len();
              match Archive::parse(&mut fd, size as usize) {
                  Ok(archive) => {
                      assert_eq!(archive.member_of_symbol("wow_so_meta_doge_symbol"), Some(GOBLIN));
                      match archive.extract(GOBLIN, &mut fd) {
                            Ok(bytes) => {
                                match elf::Elf::parse(&mut Cursor::new(&bytes)) {
                                    Ok(elf) => {
                                        assert!(elf.entry == 0);
                                        assert!(elf.bias == 0);
                                    },
                                    Err(_) => assert!(false)
                                }
                            },
                            Err(_) => assert!(false)
                     }
                  },
                  Err(err) => {println!("{:?}", err); assert!(false)}
              }
          },
           Err(_) => assert!(false)
        }
    }
}
