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

// Use lazy_parse and assembles the Elf with only parts we care
fn parse_text_section_size_lazy(base: &[u8]) -> Result<u64, &'static str> {
    let header = Elf::parse_header(base).map_err(|_| "parse elf header error")?;
    // dummy Elf with only header
    let mut obj = Elf::lazy_parse(header).map_err(|_| "cannot parse ELF file")?;

    use goblin::container::{Container, Ctx};
    use goblin::elf::SectionHeader;
    use goblin::strtab::Strtab;

    let ctx = Ctx {
        le: scroll::Endian::Little,
        container: Container::Big,
    };

    obj.section_headers =
        SectionHeader::parse(base, header.e_shoff as usize, header.e_shnum as usize, ctx)
            .map_err(|_| "parse section headers error")?;

    let strtab_idx = header.e_shstrndx as usize;
    let strtab_shdr = &obj.section_headers[strtab_idx];
    let strtab = Strtab::parse(
        base,
        strtab_shdr.sh_offset as usize,
        strtab_shdr.sh_size as usize,
        0x0,
    )
    .map_err(|_| "parse string table error")?;
    for (_, section) in obj.section_headers.iter().enumerate() {
        let section_name = strtab.get(section.sh_name).unwrap().unwrap();
        if section_name == ".text" {
            return Ok(section.sh_size);
        }
    }

    Err("Didn't find text section")
}

#[test]
fn test_parse_gnu_hash_section_64bit() {
    static ALIGNED_DATA: &AlignedData<[u8]> =
        &AlignedData(*include_bytes!("bins/elf/gnu_hash/hello.so"));

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
    static ALIGNED_DATA: &AlignedData<[u8]> =
        &AlignedData(*include_bytes!("bins/elf/gnu_hash/hello32.so"));

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

#[test]
fn test_parse_text_section_size_lazy() {
    static ALIGNED_DATA: &AlignedData<[u8]> =
        &AlignedData(*include_bytes!("bins/elf/gnu_hash/hello.so"));
    assert_eq!(parse_text_section_size_lazy(&ALIGNED_DATA.0), Ok(0x126));
}

#[test]
fn test_oom() {
    use goblin::container::{Container, Ctx};
    use scroll::Pwrite;

    fn test_oom(data: &mut [u8]) {
        let mut modified_data = data.to_vec();
        let mut elf = Elf::parse(&data).unwrap();
        let endianness = elf.header.endianness().unwrap();
        let ctx = Ctx::new(
            if elf.is_64 {
                Container::Big
            } else {
                Container::Little
            },
            endianness,
        );
        let original_e_phnum = elf.header.e_phnum;
        let original_e_shnum = elf.header.e_shnum;

        // Way too many program headers
        elf.header.e_phnum = 1000;
        modified_data
            .pwrite_with(elf.header, 0, endianness)
            .unwrap();
        assert!(Elf::parse(&modified_data).is_err());

        // Possible overflow of program headers
        elf.header.e_phnum = std::u16::MAX;
        modified_data
            .pwrite_with(elf.header, 0, endianness)
            .unwrap();
        assert!(Elf::parse(&modified_data).is_err());

        // Back to original
        elf.header.e_phnum = original_e_phnum;
        modified_data
            .pwrite_with(elf.header, 0, endianness)
            .unwrap();
        assert!(Elf::parse(&modified_data).is_ok());

        // Way too many section headers
        elf.header.e_shnum = 1000;
        modified_data
            .pwrite_with(elf.header, 0, endianness)
            .unwrap();
        assert!(Elf::parse(&modified_data).is_err());

        // Fallback to large empty section header's sh_size
        elf.header.e_shnum = 0;
        elf.section_headers[0].sh_size = std::u64::MAX;
        modified_data
            .pwrite_with(elf.header, 0, endianness)
            .unwrap();
        modified_data
            .pwrite_with(
                elf.section_headers[0].clone(),
                elf.header.e_shoff as usize,
                ctx,
            )
            .unwrap();
        assert!(Elf::parse(&modified_data).is_err());

        // Possible overflow of section headers
        elf.header.e_shnum = std::u16::MAX;
        modified_data
            .pwrite_with(elf.header, 0, endianness)
            .unwrap();
        assert!(Elf::parse(&modified_data).is_err());

        // Back to original
        elf.header.e_shnum = original_e_shnum;
        modified_data
            .pwrite_with(elf.header, 0, endianness)
            .unwrap();
        assert!(Elf::parse(&modified_data).is_ok());
    }

    let aligned_data: &mut AlignedData<[u8]> =
        &mut AlignedData(*include_bytes!("bins/elf/gnu_hash/hello32.so"));
    test_oom(&mut aligned_data.0);

    let aligned_data: &mut AlignedData<[u8]> =
        &mut AlignedData(*include_bytes!("bins/elf/gnu_hash/hello.so"));
    test_oom(&mut aligned_data.0);
}
