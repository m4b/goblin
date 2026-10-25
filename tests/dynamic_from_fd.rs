use std::fs::File;
use std::io::Write;

use goblin::elf::dynamic::dyn64;
use goblin::elf::program_header::PT_DYNAMIC;
use goblin::elf64::program_header::ProgramHeader;

// A PT_DYNAMIC segment whose declared size runs past the end of the file
// must be rejected before any allocation is sized by it. Regression test:
// from_fd previously allocated filesz / SIZEOF_DYN entries unchecked, so
// a crafted header (filesz = 2^40 here, file = 64 bytes) aborted the host
// process with a huge vec! allocation.
#[test]
fn from_fd_rejects_segment_past_eof() {
    let path = std::env::temp_dir().join("goblin_dyn_from_fd_test.bin");
    {
        let mut f = File::create(&path).unwrap();
        for i in 0..4u64 {
            f.write_all(&i.to_le_bytes()).unwrap();
            f.write_all(&(100 + i).to_le_bytes()).unwrap();
        }
    }
    let fd = File::open(&path).unwrap();
    let phdr = ProgramHeader {
        p_type: PT_DYNAMIC,
        p_offset: 0,
        p_filesz: 1 << 40,
        ..Default::default()
    };
    let res = dyn64::from_fd(&fd, &[phdr]);
    assert!(
        res.is_err(),
        "expected an error for a segment extending past EOF, got {res:?}"
    );
}

#[test]
fn from_fd_reads_segment_inside_file() {
    let path = std::env::temp_dir().join("goblin_dyn_from_fd_ok_test.bin");
    {
        let mut f = File::create(&path).unwrap();
        for i in 0..4u64 {
            f.write_all(&i.to_le_bytes()).unwrap();
            f.write_all(&(100 + i).to_le_bytes()).unwrap();
        }
    }
    let fd = File::open(&path).unwrap();
    let phdr = ProgramHeader {
        p_type: PT_DYNAMIC,
        p_offset: 0,
        p_filesz: 64,
        ..Default::default()
    };
    let res = dyn64::from_fd(&fd, &[phdr]);
    let dyns = res
        .expect("a segment inside the file should parse")
        .expect("PT_DYNAMIC should yield entries");
    assert_eq!(dyns.len(), 4);
}
