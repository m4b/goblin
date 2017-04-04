//! The Mach-o, mostly zero-copy, binary format parser and raw struct definitions

use scroll::{self, Pread};

use error;
use container;

pub mod header;
pub mod constants;
pub mod fat;
pub mod load_command;
pub mod symbols;
pub mod exports;
pub mod imports;
pub mod bind_opcodes;

pub use self::constants::cputype as cputype;

/// Returns a big endian magical number
pub fn peek<S: AsRef<[u8]>>(buffer: &S, offset: usize) -> error::Result<u32> {
    Ok(buffer.pread_with::<u32>(offset, scroll::BE)?)
}

#[derive(Debug)]
/// A cross-platform, zero-copy, endian-aware, 32/64 bit Mach-o binary parser
pub struct MachO<'a> {
    pub header: header::Header,
    pub load_commands: Vec<load_command::LoadCommand>,
    pub segments: load_command::Segments<'a>,
    pub symbols: Option<symbols::Symbols<'a>>,
    pub libs: Vec<&'a str>,
    pub entry: u64,
    pub name: Option<&'a str>,
    ctx: container::Ctx,
    export_trie: Option<exports::ExportTrie<'a>>,
    bind_interpreter: Option<imports::BindInterpreter<'a>>,
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
    /// Return the imported symbols in this binary that dyld knows about (if any)
    pub fn imports(&self) -> error::Result<Vec<imports::Import>> {
        if let Some(ref interpreter) = self.bind_interpreter {
            interpreter.imports(self.libs.as_slice(), self.segments.as_slice(), &self.ctx)
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
        let mut libs = vec!["self"];
        let mut export_trie = None;
        let mut bind_interpreter = None;
        let mut entry = 0x0;
        let mut name = None;
        let mut segments = load_command::Segments::new(ctx);
        for _ in 0..ncmds {
            let cmd = load_command::LoadCommand::parse(buffer, offset, ctx.le)?;
            match cmd.command {
                load_command::CommandVariant::Segment32(command) => {
                    segments.push(load_command::Segment::from_32(buffer.as_ref(), &command, cmd.offset, ctx))
                },
                load_command::CommandVariant::Segment64(command) => {
                    segments.push(load_command::Segment::from_64(buffer.as_ref(), &command, cmd.offset, ctx))
                },
                load_command::CommandVariant::Symtab(command) => {
                    symbols = Some(symbols::Symbols::parse(buffer, &command, ctx)?);
                },
                  load_command::CommandVariant::LoadDylib      (command)
                | load_command::CommandVariant::LoadUpwardDylib(command)
                | load_command::CommandVariant::ReexportDylib  (command)
                | load_command::CommandVariant::LazyLoadDylib  (command) => {
                    let lib = buffer.pread::<&str>(cmd.offset + command.dylib.name as usize)?;
                    libs.push(lib);
                },
                  load_command::CommandVariant::DyldInfo    (command)
                | load_command::CommandVariant::DyldInfoOnly(command) => {
                    export_trie = Some(exports::ExportTrie::new(buffer, &command));
                    bind_interpreter = Some(imports::BindInterpreter::new(buffer, &command));
                },
                load_command::CommandVariant::Unixthread(command) => {
                    entry = command.thread_state.eip as u64;
                },
                load_command::CommandVariant::Main(command) => {
                    entry = command.entryoff;
                },
                load_command::CommandVariant::IdDylib(command) => {
                    let id = buffer.pread::<&str>(cmd.offset + command.dylib.name as usize)?;
                    libs[0] = id;
                    name = Some(id);
                },
                _ => ()
            }
            cmds.push(cmd)
        }
        Ok(MachO {
            header: header,
            load_commands: cmds,
            segments: segments,
            symbols: symbols,
            libs: libs,
            export_trie: export_trie,
            bind_interpreter: bind_interpreter,
            entry: entry,
            name: name,
            ctx: ctx,
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
    // pub fn parse_at(&'a self, bytes: &'a [u8], idx: usize) -> error::Result<MachO<'a>> {
    //     match *self {
    //         Mach::Fat(arches) => {
    //             let arch = arches[idx];
    //             let start = arch.offset as usize;
    //             let end = (arch.offset + arch.size) as usize;
    //             // let bytes = arch.slice(bytes);
    //             MachO::parse(bytes, arch.offset as usize)
    //         },
    //         Mach::Binary(binary) => Ok(binary)
    //     }
    // }

    pub fn parse<'b, B: AsRef<[u8]>>(buffer: &'b B) -> error::Result<Mach<'b>> {
        let size = buffer.as_ref().len();
        if size < 4 {
            let error = error::Error::Malformed(
                                       format!("size is smaller than a magical number"));
            return Err(error);
        }
        let magic = peek(&buffer, 0)?;
        match magic {
            fat::FAT_MAGIC => {
                let arches = fat::FatArch::parse(&buffer)?;
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
