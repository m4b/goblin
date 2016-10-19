//cargo run --example=ar -- crt1.a

extern crate goblin;

//use goblin::elf64 as elf;
use goblin::archive;
use std::env;
use std::path::Path;

pub fn main () {

    let len = env::args().len();
    if len <= 1 {
        println!("usage: ar <path to archive>")
    } else {
        for (i, arg) in env::args().enumerate() {
            if i == 1 {
                let path = Path::new(arg.as_str());
                let mut fd = ::std::fs::File::open(&path).unwrap();
                let metadata = fd.metadata().unwrap();
                let archive = archive::Archive::parse(&mut fd, metadata.len() as usize);
                println!("{:#?}", archive);
            }
        }
    }
}
