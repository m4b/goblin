/// Demonstrates the power of scroll
/// Goblin implements `TryFromCtx` for the header type
/// which means downstream crates/clients can just "parse" headers out of
/// arbitrary buffers, without learning new crate specific function names
/// I.e., all you need are Types + Pread = Happiness

extern crate scroll;
extern crate goblin;

use goblin::{error, elf64, elf};
use scroll::Pread;

fn run () -> error::Result<()> {
    use Pread;
    let crt1: Vec<u8> = include!("../etc/crt1.rs");
    let header: elf64::header::Header = crt1.pread_into(0)?;
    assert_eq!(header.e_type, elf64::header::ET_REL);
    println!("header: {:?}", &header);
    // but wait, lets just pread the entire binary...
    let elf: elf::Elf = crt1.pread_into(0)?;
    // yup, that.just.happened.
    println!("elf: {:#?}", &elf);
    Ok(())
} 

fn main() {
    run().unwrap();
}
