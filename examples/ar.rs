//cargo run --example=ar -- crt1.a

extern crate goblin;

use goblin::elf;
use goblin::archive;
use std::env;
use std::path::Path;
use std::io::Cursor;

pub fn main () {
    let len = env::args().len();
    if len <= 2 {
        println!("usage: ar <path to archive> member")
    } else {
        let mut path = String::default();
        let mut member = String::default();
        for (i, arg) in env::args().enumerate() {
            if i == 1 {
                path = arg.as_str().to_owned();
            } else if i == 2 {
                member = arg.as_str().to_owned();
            }
        }
        let path = Path::new(&path);
        let mut fd = ::std::fs::File::open(&path).unwrap();
        let metadata = fd.metadata().unwrap();
        match archive::Archive::parse(&mut fd, metadata.len() as usize) {
            Ok(archive) => {
                println!("{:#?}", &archive);
                println!("start: {:?}", archive.member_of_symbol("_start"));
                match archive.extract(&member, &mut fd) {
                    Ok(bytes) => {
                        match elf::Elf::parse(&mut Cursor::new(&bytes)) {
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
