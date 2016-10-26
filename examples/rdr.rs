extern crate goblin;

use goblin::elf;
use goblin::mach;
use std::path::Path;
use std::env;

pub fn main () {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            match elf::Elf::from(&path) {
                Ok(elf) => {
                    println!("{:#?}", elf);
//                    if let Some(dynamic) = elf.dynamic {
//                        println!("len: {}", dynamic.len());
//                        for (i, dyn) in dynamic.enumerate() {
//                            println!("{}: {:?}", i, dyn.d_tag());
//                        }
//                    }
                },
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
