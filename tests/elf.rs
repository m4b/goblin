use std::slice;

use goblin::elf::section_header::SHT_GNU_HASH;
use goblin::elf::sym::Sym;
use goblin::elf::Elf;
use goblin::elf32::gnu_hash::GnuHash as GnuHash32;
use goblin::elf64::gnu_hash::GnuHash as GnuHash64;

#[repr(C)]
#[repr(align(64))] // Align to cache lines
pub struct AlignedData<T: ?Sized>(T);

fn parse_gnu_hash_section(base: &[u8], symbol_name: &str) -> Result<Sym, &'static str> {
    let obj = Elf::parse(base).map_err(|_| "cannot parse ELF file")?;
    let hash_section = obj
        .section_headers
        .iter()
        .find(|s| s.sh_type == SHT_GNU_HASH)
        .ok_or("object does not contain .gnu.hash section")?;
    let hashtab: &[u8] = unsafe {
        let addr = base.as_ptr().add(hash_section.sh_offset as usize);
        let size = hash_section.sh_size as usize;
        slice::from_raw_parts(addr, size)
    };
    let dynsyms = obj.dynsyms.to_vec();
    let section = unsafe {
        if obj.is_64 {
            GnuHash64::from_raw_table(hashtab, &dynsyms)?.find(symbol_name, &obj.dynstrtab)
        } else {
            GnuHash32::from_raw_table(hashtab, &dynsyms)?.find(symbol_name, &obj.dynstrtab)
        }
    };
    section.copied().ok_or("cannot find symbol")
}

#[test]
fn test_parse_gnu_hash_section_64bit() {
    static ALIGNED_DATA: &AlignedData<[u8]> = &AlignedData(*include_bytes!("bins/elf/gnu_hash/hello.so"));

    assert_eq!(
        parse_gnu_hash_section(&ALIGNED_DATA.0, "helloWorld"),
        Ok(Sym {
            st_name: 97,
            st_info: 0x12,
            st_other: 0,
            st_shndx: 12,
            st_value: 0x65a,
            st_size: 33,
        })
    );
    assert_eq!(
        parse_gnu_hash_section(&ALIGNED_DATA.0, "_edata"),
        Ok(Sym {
            st_name: 130,
            st_info: 0x10,
            st_other: 0,
            st_shndx: 22,
            st_value: 0x0020_1030,
            st_size: 0,
        })
    );
    assert_eq!(
        parse_gnu_hash_section(&ALIGNED_DATA.0, "__gmon_start__"),
        Err("cannot find symbol"),
    );
}

#[test]
fn test_parse_gnu_hash_section_32bit() {
    static ALIGNED_DATA: &AlignedData<[u8]> = &AlignedData(*include_bytes!("bins/elf/gnu_hash/hello32.so"));

    assert_eq!(
        parse_gnu_hash_section(&ALIGNED_DATA.0, "helloWorld"),
        Ok(Sym {
            st_name: 97,
            st_info: 0x12,
            st_other: 0,
            st_shndx: 12,
            st_value: 0x4ed,
            st_size: 49,
        })
    );
    assert_eq!(
        parse_gnu_hash_section(&ALIGNED_DATA.0, "_edata"),
        Ok(Sym {
            st_name: 130,
            st_info: 0x10,
            st_other: 0,
            st_shndx: 22,
            st_value: 0x2018,
            st_size: 0,
        })
    );
    assert_eq!(
        parse_gnu_hash_section(&ALIGNED_DATA.0, "__gmon_start__"),
        Err("cannot find symbol"),
    );
}
