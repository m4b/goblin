extern crate goblin;

use goblin::elf;
use std::path::Path;
use std::env;

pub fn main () {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let bin = elf::Elf::from_path(Path::new(arg.as_str()));
            println!("{:#?}", bin);
        }
    }
}
