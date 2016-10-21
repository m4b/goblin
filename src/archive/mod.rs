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

pub const SIZEOF_MAGIC: usize = 8;
/// The magic number of a Unix Archive
pub const MAGIC: &'static [u8; SIZEOF_MAGIC] = b"!<arch>\x0A";

const SIZEOF_FILE_IDENTIFER: usize = 16;

#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
/// A Unix Archive File Header - meta data for the file/byte blob/whatever that follows exactly after.
/// All data is right-padded with spaces ASCII `0x20`. The Binary layout is as follows:
///
/// |Offset|Length|Name                       |Format |
/// |:-----|:-----|:--------------------------|:------|
/// |0     |16    |File identifier            |ASCII  |
/// |16    |12    |File modification timestamp|Decimal|
/// |28    |6     |Owner ID                   |Decimal|
/// |34    |6     |Group ID                   |Decimal|
/// |40    |8     |File mode                  |Octal  |
/// |48    |10    |Filesize in bytes          |Decimal|
/// |58    |2     |Ending characters          |`0x60 0x0A`|
///
/// Byte alignment is according to the following:
/// > Each archive file member begins on an even byte boundary; a newline is inserted between files
/// > if necessary. Nevertheless, the size given reflects the actual size of the file exclusive
/// > of padding.
// TODO: serialize more values here
pub struct FileHeader {
    /// The identifier, or name for this file.
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
pub const SIZEOF_FILEHEADER: usize = SIZEOF_FILE_IDENTIFER + 12 + 6 + 6 + 8 + SIZEOF_FILE_SIZE + 2;

impl FileHeader {
    pub fn parse<R: Read + Seek>(cursor: &mut R) -> io::Result<FileHeader> {
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
        try!(cursor.read(&mut file_size));
        let mut terminator = [0u8; 2];
        try!(cursor.read(&mut terminator));
        let string = unsafe { ::std::str::from_utf8_unchecked(&file_size) };
        let file_size = match usize::from_str_radix(string.trim_right(), 10) {
            Ok(file_size) => file_size,
            Err(err) => return io_error!("Err: {:?} Bad file_size {:?}", err, &file_size),
        };
        Ok(FileHeader {
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
/// Represents a single file entry in the archive
pub struct File {
    /// The parsed file header
    header: FileHeader,
    /// File offset from the start of the archive to where the file begins
    pub offset: u64,
}

impl File {
    /// Tries to parse the header in `R`, as well as the offset in `R.
    /// **NOTE** the Seek will be pointing at the first byte of whatever the file is, skipping padding.
    pub fn parse<R: Read + Seek>(cursor: &mut R) -> io::Result<File> {
        let header = try!(FileHeader::parse(cursor));
        let mut offset = try!(cursor.seek(Current(0)));
        // skip newline padding if we're on an uneven byte boundary
        if offset & 1 == 1 {
            offset = try!(cursor.seek(Current(1)));
        }
        Ok(File {
            header: header,
            offset: offset,
        })
    }

    /// The size of the File's content, in bytes. Does **not** include padding, nor the size of the
    /// file header.
    pub fn size(&self) -> usize {
        self.header.size
    }

    pub fn name(&self) -> &str {
        &self.header.identifier
    }

}

#[derive(Debug, Default)]
/// The special index member signified by the name `"/"`.
/// The data element contains a list of symbol indexes and symbol names, giving their offsets
/// into the archive for a given name.
// TODO: make this into a hashmap from string -> (file_name, offset) indexes?
pub struct Index {
    /// Big Endian number of symbol_indexes and strings
    pub size: usize,
    /// Big Endian u32 index into the archive for this symbol (index in array is the index into the string table)
    pub symbol_indexes: Vec<u32>,
    /// Set of zero-terminated strings indexed by above. Number of strings = `self.size`
    pub strtab: strtab::Strtab<'static>,
}

/// SysV Archive Variant Symbol Lookup Table "Magic" Name
pub const SYMBOL_LOOKUP_MAGIC: &'static [u8; SIZEOF_FILE_IDENTIFER] = b"/               ";
pub const SYMBOL_LOOKUP_NAME: &'static str = "/               ";

impl Index {
    pub fn parse<'c, R: Read + Seek>(cursor: &'c mut R, size: usize) -> io::Result<Index> {
        let sizeof_table = try!(cursor.read_u32::<BigEndian>()) as usize;
        let mut indexes = Vec::with_capacity(sizeof_table);
        for _ in 0..sizeof_table {
            indexes.push(try!(cursor.read_u32::<BigEndian>()));
        }
        let sizeof_strtab = size - ((sizeof_table * 4) + 4);
        let offset = try!(cursor.seek(Current(0)));
        let strtab = try!(strtab::Strtab::parse(cursor, offset as usize, sizeof_strtab));
        Ok (Index {
            size: sizeof_table,
            symbol_indexes: indexes,
            strtab: strtab,
        })
    }
}

#[derive(Debug)]
pub struct Archive {
    pub index: Index,
    files: HashMap<String, File>,
}

impl Archive {
    pub fn parse<R: Read + Seek>(mut cursor: &mut R, size: usize) -> io::Result<Archive> {
        try!(cursor.seek(Start(0)));
        let mut magic = [0; SIZEOF_MAGIC];
        try!(cursor.read_exact(&mut magic));
        if &magic != MAGIC {
            return io_error!("Invalid Archive magic number: {:?}", &magic);
        }
        let mut files = HashMap::new();
        let size = size as u64;
        let mut pos = 0u64;
        loop {
            if pos >= size { break }
            let file = try!(File::parse(&mut cursor));
            let size = file.size() as i64;
            files.insert(file.name().to_owned(), file);
            // we move the cursor past the file blob
            pos = try!(cursor.seek(Current(size)));
        }

        let mut index = Index::default();
        if let Some(file) = files.get(SYMBOL_LOOKUP_NAME) {
            let mut data = vec![0u8; file.size()];
            try!(cursor.seek(Start(file.offset)));
            try!(cursor.read_exact(&mut data));
            let mut data = Cursor::new(&data);
            index = try!(Index::parse(&mut data, file.size()));
        }
        let archive = Archive {
            index: index,
            files: files,
        };
        Ok(archive)
    }

    pub fn get (&self, member: &str) -> Option<&File> {
        self.files.get(member)
    }

    pub fn extract<R: Read + Seek> (&self, member: &str, cursor: &mut R) -> io::Result<Vec<u8>> {
        if let Some(file) = self.get(member) {
            let mut bytes = vec![0u8; file.size()];
            try!(cursor.seek(Start(file.offset)));
            try!(cursor.read_exact(&mut bytes));
            Ok(bytes)
        } else {
            return io_error!(format!("Error: cannot extract member {}, not found", member));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parse_file_header() {
        let file_header: [u8; SIZEOF_FILEHEADER] = [0x2f, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                                    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                                    0x20, 0x20, 0x30, 0x20, 0x20, 0x20, 0x20,
                                                    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                                    0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x30,
                                                    0x20, 0x20, 0x20, 0x20, 0x20, 0x30, 0x20,
                                                    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x38,
                                                    0x32, 0x34, 0x34, 0x20, 0x20, 0x20, 0x20,
                                                    0x20, 0x20, 0x60, 0x0a];
        let mut cursor = Cursor::new(&file_header[..]);
        match FileHeader::parse(&mut cursor) {
            Err(_) => assert!(false),
            Ok(file_header2) => {
                let file_header = FileHeader { identifier: "/               ".to_owned(),
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
        let crt1a: Vec<u8> = include!("../../crt1a.rs");
        let mut cursor = Cursor::new(&crt1a);
        match Archive::parse(&mut cursor, crt1a.len()) {
            Ok(archive) => {
                if let Some(file) = archive.get("crt1.o/         ") {
                    assert_eq!(file.offset, 194);
                    assert_eq!(file.size(), 1928)
                } else {
                    assert!(false)
                }
            },
            Err(_) => assert!(false),
        };
    }
}
