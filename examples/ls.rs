extern crate goblin;

use goblin::elf;
use std::path::Path;

pub fn main () {
    let ls = elf::Elf::from_path(Path::new("/bin/ls"));
    println!("{:#?}", ls);
}
