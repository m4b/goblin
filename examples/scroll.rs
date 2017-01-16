/// Demonstrates the magical powers of scroll + goblin
/// Goblin implements `TryFromCtx` for the header type
/// which means downstream crates/clients can just "parse" headers out of
/// arbitrary buffers, without learning new crate specific function names
/// I.e., all you need are Types + Pread = Happiness

extern crate scroll;
extern crate goblin;

use goblin::{error, elf64, elf};
use scroll::{Pwrite, Pread};

fn run () -> error::Result<()> {
    use Pread;
    let crt1: Vec<u8> = include!("../etc/crt1.rs");
    let header: elf64::header::Header = crt1.pread_into(0)?;
    assert_eq!(header.e_type, elf64::header::ET_REL);
    println!("header: {:?}", &header);
    // now lets write the header into some bytes
    let mut bytes = [0u8; elf64::header::SIZEOF_EHDR];
    bytes.pwrite_into(header, 0)?;
    // read it back out
    let header2: elf64::header::Header = bytes.pread_into(0)?;
    // they're the same
    assert_eq!(header, header2);
    // but wait, lets just pread the entire binary...
    let elf: elf::Elf = crt1.pread_into(0)?;
    // yup, that.just.happened.
    println!("elf: {:#?}", &elf);
    Ok(())
} 

fn main() {
    run().unwrap();
}
