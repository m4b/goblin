//cargo run --example=ar -- crt1.a

extern crate goblin;

use goblin::elf;
use goblin::archive;
use std::env;
use std::path::Path;
use std::io::Cursor;

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
                match archive::Archive::parse(&mut fd, metadata.len() as usize) {
                    Ok(archive) => {
                        println!("{:#?}", &archive);
                        match archive.extract(&"rust.metadata.bin", &mut fd) {
                            Ok(bytes) => {
                                match elf::parse(&mut Cursor::new(&bytes)) {
                                    Ok(elf) => {
                                        println!("got elf: {:#?}", elf);
                                    },
                                    Err(err) => println!("Err: {:?}", err)
                                }
                            },
                            Err(err) => println!("Extraction Error: {:?}", err)
                        }
                    },
                    Err(err) => println!("Err: {:?}", err)
                }
            }
        }
    }
}
