//! The mach module: Work in Progress!

use std::io::Read;
use scroll::{self, Pread};

use error;
//use container::{self, Container};

pub mod header;
pub mod constants;
pub mod fat;
pub mod utils;
pub mod load_command;
// pub mod section;
// pub mod symbol;

#[derive(Debug)]
pub struct MachO {
    pub header: header::Header,
    pub load_commands: Vec<load_command::LoadCommand>,
}

impl MachO {
    pub fn parse<'a, B: AsRef<[u8]>> (buffer: &'a B, mut offset: usize) -> error::Result<Self> {
        let offset = &mut offset;
        let header: header::Header = buffer.pread(*offset)?;
        let ctx = header.ctx()?;
        *offset = *offset + header.size();
        let ncmds = header.ncmds;
        let mut cmds: Vec<load_command::LoadCommand> = Vec::with_capacity(ncmds);
        for _ in 0..ncmds {
            let cmd = load_command::LoadCommand::parse(buffer, offset, ctx.le)?;
            cmds.push(cmd)
        }
        Ok(MachO { header: header, load_commands: cmds })
    }
}

#[derive(Debug)]
/// Either a fat collection of architectures, or a single mach-o binary
pub enum Mach {
    Fat(Vec<fat::FatArch>),
    Binary(MachO)
}

impl Mach {
    pub fn parse<'b, B: AsRef<[u8]>>(buffer: &'b B) -> error::Result<Mach> {
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
    pub fn try_from<R: Read>(fd: &mut R) -> error::Result<Mach> {
        let buffer = scroll::Buffer::try_from(fd)?;
        Self::parse(&buffer)
    }
}
