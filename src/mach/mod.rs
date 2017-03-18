//! The mach module: Work in Progress!

use scroll::{Pread};

use error;
//use container::{self, Container};

pub mod header;
pub mod constants;
pub mod fat;
pub mod utils;
pub mod load_command;
pub mod symbols;

#[derive(Debug)]
/// A zero-copy, endian-aware, 32/64 bit Mach-o binary parser
pub struct MachO<'a> {
    pub header: header::Header,
    pub load_commands: Vec<load_command::LoadCommand>,
    pub symbols: Option<symbols::Symbols<'a>>,
}

impl<'a> MachO<'a> {
    pub fn parse<'b, B: AsRef<[u8]>> (buffer: &'b B, mut offset: usize) -> error::Result<MachO<'b>> {
        let offset = &mut offset;
        let header: header::Header = buffer.pread(*offset)?;
        let ctx = header.ctx()?;
        *offset = *offset + header.size();
        let ncmds = header.ncmds;
        let mut cmds: Vec<load_command::LoadCommand> = Vec::with_capacity(ncmds);
        let mut symbols = None;
        for _ in 0..ncmds {
            let cmd = load_command::LoadCommand::parse(buffer, offset, ctx.le)?;
            match cmd.command {
                load_command::CommandVariant::Symtab(command) => {
                    symbols = Some(symbols::Symbols::parse(buffer, &command, ctx)?);
                },
                _ => ()
            }
            cmds.push(cmd)
        }
        Ok(MachO { header: header, load_commands: cmds, symbols: symbols })
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
