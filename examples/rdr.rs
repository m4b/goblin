extern crate goblin;
extern crate scroll;

use goblin::error;
use std::path::Path;
use std::env;
use std::fs::File;
use scroll::{Buffer};

fn run () -> error::Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let fd = File::open(path)?;
            let buffer = Buffer::try_from(fd)?;
            let res = goblin::parse(&buffer)?;
            println!("res: {:#?}", res);
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
