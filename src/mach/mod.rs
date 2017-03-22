//! The Mach-o binary format parser and raw struct definitions

use scroll::{Pread};

use error;
//use container::{self, Container};

pub mod header;
pub mod constants;
pub mod fat;
pub mod utils;
pub mod load_command;
pub mod symbols;
pub mod exports;

pub use self::constants::cputype as cputype;

#[derive(Debug)]
/// A zero-copy, endian-aware, 32/64 bit Mach-o binary parser
pub struct MachO<'a> {
    pub header: header::Header,
    pub load_commands: Vec<load_command::LoadCommand>,
    pub symbols: Option<symbols::Symbols<'a>>,
    pub libs: Vec<&'a str>,
    pub entry: u64,
    export_trie: Option<exports::ExportTrie<'a>>,
}

impl<'a> MachO<'a> {
    /// Return the exported symbols in this binary (if any)
    pub fn exports(&self) -> error::Result<Vec<exports::Export>> {
        if let Some(ref trie) = self.export_trie {
            trie.exports(self.libs.as_slice())
        } else {
            Ok(vec![])
        }
    }
    /// Parses the Mach-o binary from `buffer` at `offset`
    pub fn parse<'b, B: AsRef<[u8]>> (buffer: &'b B, mut offset: usize) -> error::Result<MachO<'b>> {
        let offset = &mut offset;
        let header: header::Header = buffer.pread(*offset)?;
        let ctx = header.ctx()?;
        *offset = *offset + header.size();
        let ncmds = header.ncmds;
        let mut cmds: Vec<load_command::LoadCommand> = Vec::with_capacity(ncmds);
        let mut symbols = None;
        let mut libs = Vec::new();
        let mut export_trie = None;
        let mut entry = 0x0;
        for _ in 0..ncmds {
            let cmd = load_command::LoadCommand::parse(buffer, offset, ctx.le)?;
            match cmd.command {
                load_command::CommandVariant::Symtab(command) => {
                    symbols = Some(symbols::Symbols::parse(buffer, &command, ctx)?);
                },
                  load_command::CommandVariant::LoadDylib    (command)
                | load_command::CommandVariant::ReexportDylib(command)
                | load_command::CommandVariant::LazyLoadDylib(command) => {
                    let lib = buffer.pread::<&str>(cmd.offset + command.dylib.name as usize)?;
                    libs.push(lib);
                },
                  load_command::CommandVariant::DyldInfo    (command)
                | load_command::CommandVariant::DyldInfoOnly(command) => {
                    export_trie = Some(exports::ExportTrie::new(buffer, &command)?);
                },
                load_command::CommandVariant::Main(command) => {
                    entry = command.entryoff;
                }
                _ => ()
            }
            cmds.push(cmd)
        }
        Ok(MachO {
            header: header,
            load_commands: cmds,
            symbols: symbols,
            libs: libs,
            export_trie: export_trie,
            entry: entry,
        })
    }
}

#[derive(Debug)]
/// Either a fat collection of architectures, or a single mach-o binary
pub enum Mach<'a> {
    Fat(Vec<fat::FatArch>),
    Binary(MachO<'a>)
}

impl<'a> Mach<'a> {
    pub fn parse<'b, B: AsRef<[u8]>>(buffer: &'b B) -> error::Result<Mach<'b>> {
        let size = buffer.as_ref().len();
        if size < 4 {
            let error = error::Error::Malformed(
                                       format!("size is smaller than a magical number"));
            return Err(error);
        }
        let magic = utils::peek_magic(&buffer, 0)?;
        match magic {
            fat::FAT_CIGAM => {
                let arches = fat::FatArch::parse(&buffer)?;
                println!("{:?}", arches);
                Ok(Mach::Fat(arches))
            },
            // we're a regular binary
            _ => {
                let binary = MachO::parse(buffer, 0)?;
                Ok(Mach::Binary(binary))
            }
        }
    }
}
