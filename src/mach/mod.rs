//! The Mach-o, mostly zero-copy, binary format parser and raw struct definitions
use core::fmt;

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
pub fn peek<B: AsRef<[u8]>>(bytes: B, offset: usize) -> error::Result<u32> {
    Ok(bytes.pread_with::<u32>(offset, scroll::BE)?)
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
    pub little_endian: bool,
    pub is_64: bool,
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
    /// Parses the Mach-o binary from `bytes` at `offset`
    pub fn parse(bytes: &'a [u8], mut offset: usize) -> error::Result<MachO<'a>> {
        let offset = &mut offset;
        let header: header::Header = bytes.pread(*offset)?;
        let ctx = header.ctx()?;
        let little_endian = ctx.le.is_little();
        let is_64 = ctx.container.is_big();
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
            let cmd = load_command::LoadCommand::parse(bytes, offset, ctx.le)?;
            match cmd.command {
                load_command::CommandVariant::Segment32(command) => {
                    segments.push(load_command::Segment::from_32(bytes.as_ref(), &command, cmd.offset, ctx))
                },
                load_command::CommandVariant::Segment64(command) => {
                    segments.push(load_command::Segment::from_64(bytes.as_ref(), &command, cmd.offset, ctx))
                },
                load_command::CommandVariant::Symtab(command) => {
                    symbols = Some(symbols::Symbols::parse(bytes, &command, ctx)?);
                },
                  load_command::CommandVariant::LoadDylib      (command)
                | load_command::CommandVariant::LoadUpwardDylib(command)
                | load_command::CommandVariant::ReexportDylib  (command)
                | load_command::CommandVariant::LazyLoadDylib  (command) => {
                    let lib = bytes.pread::<&str>(cmd.offset + command.dylib.name as usize)?;
                    libs.push(lib);
                },
                  load_command::CommandVariant::DyldInfo    (command)
                | load_command::CommandVariant::DyldInfoOnly(command) => {
                    export_trie = Some(exports::ExportTrie::new(bytes, &command));
                    bind_interpreter = Some(imports::BindInterpreter::new(bytes, &command));
                },
                load_command::CommandVariant::Unixthread(command) => {
                    entry = command.thread_state.eip as u64;
                },
                load_command::CommandVariant::Main(command) => {
                    entry = command.entryoff;
                },
                load_command::CommandVariant::IdDylib(command) => {
                    let id = bytes.pread::<&str>(cmd.offset + command.dylib.name as usize)?;
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
            is_64: is_64,
            little_endian: little_endian,
        })
    }
}

#[cfg(feature = "std")]
/// A Mach-o multi architecture (Fat) binary container
pub struct MultiArch<'a> {
    data: &'a [u8],
    start: usize,
    pub narches: usize,
}

/// Iterator over the fat architecture headers in a `MultiArch` container
pub struct FatArchIterator<'a> {
    index: usize,
    data: &'a[u8],
    narches: usize,
    start: usize,
}

impl<'a> Iterator for FatArchIterator<'a> {
    type Item = scroll::Result<fat::FatArch>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.narches {
            None
        } else {
            let offset = (self.index * fat::SIZEOF_FAT_ARCH) + self.start;
            let arch = self.data.pread_with::<fat::FatArch>(offset, scroll::BE);
            self.index += 1;
            Some(arch)
        }
    }
}

impl<'a, 'b> IntoIterator for &'b MultiArch<'a> {
    type Item = scroll::Result<fat::FatArch>;
    type IntoIter = FatArchIterator<'a>;
    fn into_iter(self) -> Self::IntoIter {
        FatArchIterator {
            index: 0,
            data: self.data,
            narches: self.narches,
            start: self.start,
        }
    }
}

#[cfg(feature = "std")]
impl<'a> MultiArch<'a> {
    /// Lazily construct `Self`
    pub fn new(bytes: &'a [u8]) -> error::Result<Self> {
        let header = fat::FatHeader::parse(bytes)?;
        Ok(MultiArch {
            data: bytes,
            start: fat::SIZEOF_FAT_HEADER,
            narches: header.nfat_arch as usize
        })
    }
    /// Return all the architectures in this binary
    pub fn arches(&self) -> error::Result<Vec<fat::FatArch>> {
        let mut arches = Vec::with_capacity(self.narches);
        for arch in self.into_iter() {
            arches.push(arch?);
        }
        Ok(arches)
    }
    /// Try to get the Mach-o binary at `index`
    pub fn get(&self, index: usize) -> error::Result<MachO> {
        if index >= self.narches {
            return Err(error::Error::Malformed(format!("Requested the {}-th binary, but there are only {} architectures in this container", index, self.narches).into()))
        }
        let offset = (index * fat::SIZEOF_FAT_ARCH) + self.start;
        let arch = self.data.pread_with::<fat::FatArch>(offset, scroll::BE)?;
        let bytes = arch.slice(self.data);
        Ok(MachO::parse(bytes, 0)?)
    }

    /// Try and find the `cputype` in `Self`, if there is one
    pub fn find_cputype(&self, cputype: u32) -> error::Result<Option<fat::FatArch>> {
        for arch in self.into_iter() {
            let arch = arch?;
            if arch.cputype == cputype { return Ok(Some(arch)) }
        }
        Ok(None)
    }
}

#[cfg(feature = "std")]
impl<'a> fmt::Debug for MultiArch<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("MultiArch")
            .field("arches",  &self.arches().unwrap())
            .field("data",    &self.data.len())
            .finish()
    }
}

#[derive(Debug)]
/// Either a collection of multiple architectures, or a single mach-o binary
pub enum Mach<'a> {
    Fat(MultiArch<'a>),
    Binary(MachO<'a>)
}

impl<'a> Mach<'a> {
    pub fn parse(bytes: &'a [u8]) -> error::Result<Self> {
        let size = bytes.len();
        if size < 4 {
            let error = error::Error::Malformed(
                                       format!("size is smaller than a magical number"));
            return Err(error);
        }
        let magic = peek(&bytes, 0)?;
        match magic {
            fat::FAT_MAGIC => {
                let multi = MultiArch::new(bytes)?;
                Ok(Mach::Fat(multi))
            },
            // we're a regular binary
            _ => {
                let binary = MachO::parse(bytes, 0)?;
                Ok(Mach::Binary(binary))
            }
        }
    }
}
