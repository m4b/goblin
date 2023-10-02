use std::borrow::Cow;

use goblin::pe::{
    section_table::{Section, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ},
    writer::PEWriter,
    PE,
};

fn main() {
    stderrlog::new().verbosity(3).init().unwrap();
    let args: Vec<String> = std::env::args().collect();

    let file = std::fs::read(&args[1]).unwrap();
    let file = &file[..];
    let pe = PE::parse(file).unwrap();
    println!("{}", file.len());
    let mut pe_writer = PEWriter::new(pe).expect("Failed to create a wrapper");

    let section_name: [u8; 8] = *b".added\0\0";
    pe_writer
        .insert_section(
            Section::new(
                &section_name,
                Some(Cow::Borrowed(&[0x0])),
                IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            )
            .expect("Failed to create a section"),
        )
        .unwrap();

    let new_pe = pe_writer.write_into().unwrap();
    std::fs::write(&args[2], &new_pe[..]).unwrap();

    let old_pe_reread = PE::parse(&new_pe).unwrap();
    let section = old_pe_reread
        .sections
        .into_iter()
        .find(|s| s.name().expect("Failed to obtain name of a section") == ".added")
        .expect("Failed to find written section");

    let data = section
        .data(&new_pe)
        .expect("Failed to read section data")
        .expect("Failed to obtain section data");
    assert!(
        data[0] == 0x0,
        "Invalid data written in the section, got: {:?}",
        data
    );
}
