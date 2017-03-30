extern crate goblin;
extern crate scroll;

use goblin::{error, Hint, pe, elf, mach, archive};
use std::path::Path;
use std::env;
use std::fs::File;
use scroll::{Gread, Buffer};

fn run () -> error::Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let fd = File::open(path)?;
            let buffer = Buffer::try_from(fd)?;
            let mut bytes = [0; 16];
            buffer.gread_inout(&mut 0, &mut bytes)?;
            match goblin::peek_bytes(&bytes)? {
                Hint::Elf(_) => {
                    let elf = elf::Elf::parse(&buffer)?;
                    println!("elf: {:#?}", &elf);
                },
                Hint::PE => {
                    let pe = pe::PE::parse(&buffer)?;
                    println!("pe: {:#?}", &pe);
                },
                Hint::Mach(_) | Hint::MachFat(_) => {
                    let mach = mach::Mach::parse(&buffer)?;
                    println!("mach: {:#?}", &mach);
                },
                Hint::Archive => {
                    let archive = archive::Archive::parse(&buffer)?;
                    println!("archive: {:#?}", &archive);
                },
                Hint::Unknown(magic) => {
                    println!("unknown magic: {:#x}", magic)
                }
            }
        }
    }
    Ok(())
}

pub fn main () {
    match run() {
        Ok(()) => (),
        Err(err) => println!("{:#}", err)
    }
}
