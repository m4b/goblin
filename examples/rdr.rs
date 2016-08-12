extern crate goblin;

use goblin::elves;
use goblin::mach;
use std::path::Path;
use std::env;

pub fn main () {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            // we hackin' for now
            match elves::parse(path) {
                Ok(elf) => println!("{:#?}", elf),
                Err(_) => {
                    match mach::Mach::from_path(path) {
                        Ok(mach) => println!("{:#?}", mach),
                        Err(err) => println!("{:?}", err),
                    }
                },
            }
        }
    }
}
