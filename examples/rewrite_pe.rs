use goblin::pe::PE;
use scroll::Pwrite;

fn main() {
    stderrlog::new().verbosity(1).init().unwrap();
    let args: Vec<String> = std::env::args().collect();

    let file = std::fs::read(&args[1]).unwrap();
    let file = &file[..];
    let pe = PE::parse(file).unwrap();
    println!("read {}", &args[1]);

    println!(
        "file alignment: {:?}",
        pe.header
            .optional_header
            .unwrap()
            .windows_fields
            .file_alignment
    );

    let mut new_pe = vec![0u8; file.len() + 8192];
    let new_len = new_pe.pwrite(pe, 0).unwrap();
    let pe = PE::parse(file).unwrap();

    let out = &new_pe[..new_len];
    std::fs::write(&args[2], &out).unwrap();
    println!("written as {}", &args[2]);
    println!(
        "original PE size: {} bytes, new PE size: {} bytes, delta (new - original): {} bytes",
        file.len(),
        out.len(),
        out.len() as isize - file.len() as isize
    );

    let new_pe = PE::parse(&new_pe).unwrap();
    println!(
        "original signatures: {}, new signatures: {}",
        pe.certificates.len(),
        new_pe.certificates.len()
    );
}
