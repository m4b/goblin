extern crate goblin;
extern crate scroll;

use goblin::{error, Hint, pe, elf, mach, archive};
use std::path::Path;
use std::env;
use std::fs::File;
use scroll::Buffer;

fn run () -> error::Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let mut fd = File::open(path)?;
            match goblin::peek(&mut fd)? {
                Hint::Elf(_) => {
                    let elf = elf::Elf::try_from(&mut fd)?;
                    println!("elf: {:#?}", &elf);
                },
                Hint::PE => {
                    let pe = pe::PE::try_from(&mut fd)?;
                    println!("pe: {:#?}", &pe);
                },
                // wip
                Hint::Mach(_) | Hint::MachFat => {
                    //let mach = mach::Mach::try_from(&mut fd)?;
                    let buffer = Buffer::try_from(fd)?;
                    let mach = mach::Mach::parse(&buffer)?;
                    println!("mach: {:#?}", &mach);
                },
                Hint::Archive => {
                    let archive = archive::Archive::try_from(&mut fd)?;
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
