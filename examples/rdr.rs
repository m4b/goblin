extern crate goblin;

use goblin::elf;
use goblin::mach;
use std::path::Path;
use std::env;

pub fn main () {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            // we hackin' for now
            let mut fd = ::std::fs::File::open(&path).unwrap();
            match elf::from_fd(&mut fd) {
                Ok(elf) => println!("{:#?}", elf),
                Err(err) => {
                    println!("Not an ELF: {:?}", err);
                    match mach::Mach::from_path(path) {
                        Ok(mach) => println!("{:#?}", mach),
                        Err(err) => println!("{:?}", err),
                    }
                },
            }
        }
    }
}
