extern crate scroll;
extern crate goblin;
use goblin::archive::*;
use goblin::elf;
use scroll::Pread;
use std::path::Path;
use std::fs::File;

#[test]
fn parse_file_header() {
    let file_header: [u8; SIZEOF_HEADER] = [0x2f, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                            0x20, 0x20, 0x30, 0x20, 0x20, 0x20, 0x20,
                                            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                            0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x30,
                                            0x20, 0x20, 0x20, 0x20, 0x20, 0x30, 0x20,
                                            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x38,
                                            0x32, 0x34, 0x34, 0x20, 0x20, 0x20, 0x20,
                                            0x20, 0x20, 0x60, 0x0a];
    let buffer = &file_header[..];
    match buffer.pread::<MemberHeader>(0) {
        Err(_) => assert!(false),
        Ok(file_header2) => {
            let file_header = MemberHeader {
                identifier: [0x2f,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,],
                timestamp: [48, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32],
                owner_id: [48, 32, 32, 32, 32, 32],
                group_id: [48, 32, 32, 32, 32, 32],
                mode: [48, 32, 32, 32, 32, 32, 32, 32],
                file_size: [56, 50, 52, 52, 32, 32, 32, 32, 32, 32],
                terminator: [96, 10] };
            assert_eq!(file_header, file_header2)
        }
    }
}

#[test]
fn parse_archive() {
    let crt1a: Vec<u8> = include!("../etc/crt1a.rs");
    const START: &'static str = "_start";
    match Archive::parse(&crt1a) {
        Ok(archive) => {
            assert_eq!(archive.member_of_symbol(START), Some("crt1.o"));
            if let Some(member) = archive.get("crt1.o") {
                assert_eq!(member.offset, 194);
                assert_eq!(member.size(), 1928)
            } else {
                println!("could not get crt1.o");
                assert!(false)
            }
        },
        Err(err) => {println!("could not parse archive: {:?}", err); assert!(false)}
    };
}

#[test]
fn parse_self_wow_so_meta_doge() {
    use std::io::Read;
    let path = Path::new("target").join("debug").join("libgoblin.rlib");
    match File::open(path) {
        Ok(mut fd) => {
            let buffer = { let mut v = Vec::new(); fd.read_to_end(&mut v).unwrap(); v};
            match Archive::parse(&buffer) {
                Ok(archive) => {
                    let mut found = false;
                    for member in archive.members() {
                        if member.starts_with("goblin") && member.ends_with("0.o") {
                            assert_eq!(archive.member_of_symbol("wow_so_meta_doge_symbol"), Some(member.as_str()));
                            match archive.extract(member.as_str(), &buffer) {
                                Ok(bytes) => {
                                    match elf::Elf::parse(&bytes) {
                                        Ok(elf) => {
                                            assert!(elf.entry == 0);
                                            assert!(elf.bias == 0);
                                            found = true;
                                            break;
                                        },
                                        Err(err) => {
                                            println!("{:?}", err);
                                            #[cfg(target_os="linux")]
                                            assert!(false)
                                        }
                                    }
                                },
                                Err(_) => assert!(false)
                            }
                        }
                    }
                    if !found {
                        println!("goblin-<hash>.0.o not found");
                        assert!(false)
                    }
                },
                Err(err) => {println!("{:?}", err); assert!(false)}
            }
        },
        Err(err) => {println!("{:?}", err); assert!(false)}
    }
}
