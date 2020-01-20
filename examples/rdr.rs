use goblin::error;
use std::env;
use std::fs;
use std::path::Path;

fn run() -> error::Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let buffer = fs::read(path)?;
            let res = goblin::Object::parse(&buffer)?;
            println!("{:#?}", res);
        }
    }
    Ok(())
}

pub fn main() {
    match run() {
        Ok(()) => (),
        Err(err) => println!("{:#}", err),
    }
}
