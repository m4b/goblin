extern crate goblin;

use goblin::{error, Hint, pe, elf, mach, archive};
use std::path::Path;
use std::env;
use std::fs::File;

fn run () -> error::Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let mut fd = File::open(path)?;
            match goblin::peek(&mut fd)? {
                Hint::Elf => {
                    let elf = elf::Elf::try_from(&mut fd)?;
                    println!("elf: {:#?}", &elf);
                },
                Hint::PE => {
                    let pe = pe::PE::try_from(&mut fd)?;
                    println!("pe: {:#?}", &pe);
                },
                // wip
                Hint::Mach => {
                    let mach = mach::Mach::try_from(&mut fd)?;
                    println!("mach: {:#?}", &mach);
                },
                Hint::Archive => {
                    let archive = archive::Archive::try_from(&mut fd)?;
                    println!("archive: {:#?}", &archive);
                },
                _ => {}
            }
        }
    }
    Ok(())
}

pub fn main () {
    match run() {
        Ok(()) => (),
        Err(err) => println!("{:?}", err)
    }
}
