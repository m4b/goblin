/// Demonstrates parsing elf file in a lazy manner by reading only the needed parts.
/// Lets's say we just want to know the interpreter for an elf file.
/// Steps:
///     1. cd tests/bins/elf/gnu_hash/ && gcc -o hello helloworld.c
///     2. cargo run --example=lazy_parse
use goblin::container::{Container, Ctx};
use goblin::elf::*;
use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const ELF64_HDR_SIZE: usize = 64;

fn main() -> Result<(), &'static str> {
    let mut file = File::open("tests/bins/elf/gnu_hash/hello").map_err(|_| "open file error")?;
    let file_len = file.metadata().map_err(|_| "get metadata error")?.len();

    // init the content vec
    let mut contents = vec![0; file_len as usize];

    // read in header only
    file.read_exact(&mut contents[..ELF64_HDR_SIZE])
        .map_err(|_| "read header error")?;

    // parse header
    let header = Elf::parse_header(&contents).map_err(|_| "parse elf header error")?;
    if header.e_phnum == 0 {
        return Err("ELF doesn't have any program segments");
    }

    // read in program header table
    let program_hdr_table_size = header.e_phnum * header.e_phentsize;
    file.seek(SeekFrom::Start(header.e_phoff))
        .map_err(|_| "seek error")?;
    file.read_exact(
        &mut contents[ELF64_HDR_SIZE..ELF64_HDR_SIZE + (program_hdr_table_size as usize)],
    )
    .map_err(|_| "read program header table error")?;

    // dummy Elf with only header
    let mut elf = Elf::lazy_parse(header).map_err(|_| "cannot parse ELF file")?;

    let ctx = Ctx {
        le: scroll::Endian::Little,
        container: Container::Big,
    };

    // parse and assemble the program headers
    elf.program_headers = ProgramHeader::parse(
        &contents,
        header.e_phoff as usize,
        header.e_phnum as usize,
        ctx,
    )
    .map_err(|_| "parse program headers error")?;

    let mut intepreter_count = 0;
    let mut intepreter_offset = 0;
    for ph in &elf.program_headers {
        // read in interpreter segment
        if ph.p_type == program_header::PT_INTERP && ph.p_filesz != 0 {
            intepreter_count = ph.p_filesz as usize;
            intepreter_offset = ph.p_offset as usize;
            file.seek(SeekFrom::Start(intepreter_offset as u64))
                .map_err(|_| "seek error")?;
            file.read_exact(&mut contents[intepreter_offset..intepreter_offset + intepreter_count])
                .map_err(|_| "read interpreter segment error")?;
            break;
        }
    }

    // assemble the interpreter
    elf.interpreter = if intepreter_count == 0 {
        None
    } else {
        let cstr: &CStr = CStr::from_bytes_with_nul(
            &contents[intepreter_offset..intepreter_offset + intepreter_count],
        )
        .map_err(|_| "invalid interpreter path")?;
        cstr.to_str().ok()
    };

    // print result
    println!("interpreter is {:?}", elf.interpreter);

    Ok(())
}
