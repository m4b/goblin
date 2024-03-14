use goblin::elf::section_header::{SHN_XINDEX, SHT_GNU_HASH};
use goblin::elf::sym::{Sym, Symtab};
use goblin::elf::symver::{VerdefSection, VerneedSection, VersymSection};
use goblin::elf::Elf;
use goblin::elf32::gnu_hash::GnuHash as GnuHash32;
use goblin::elf64::gnu_hash::GnuHash as GnuHash64;
use goblin::strtab::Strtab;

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
    let (start, length) = (
        hash_section.sh_offset as usize,
        hash_section.sh_size as usize,
    );
    let hashtab: &[u8] = &base[start..(start + length)];
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

    let ctx = Ctx {
        le: scroll::Endian::Little,
        container: Container::Big,
    };

    obj.section_headers =
        SectionHeader::parse(base, header.e_shoff as usize, header.e_shnum as usize, ctx)
            .map_err(|_| "parse section headers error")?;

    let strtab_idx = if header.e_shstrndx as u32 == SHN_XINDEX {
        obj.section_headers[0].sh_link as usize
    } else {
        header.e_shstrndx as usize
    };

    let strtab_shdr = &obj.section_headers[strtab_idx];
    let strtab = Strtab::parse(
        base,
        strtab_shdr.sh_offset as usize,
        strtab_shdr.sh_size as usize,
        0x0,
    )
    .map_err(|_| "parse string table error")?;
    for (_, section) in obj.section_headers.iter().enumerate() {
        let section_name = strtab.get_at(section.sh_name).unwrap();
        if section_name == ".text" {
            return Ok(section.sh_size);
        }
    }

    Err("Didn't find text section")
}

fn parse_from_text_section_size_lazy(base: &[u8]) -> Result<bool, &'static str> {
    let header = Elf::parse_header(base).map_err(|_| "parse elf header error")?;

    use goblin::container::{Container, Ctx};
    use goblin::elf::SectionHeader;

    let ctx = Ctx {
        le: scroll::Endian::Little,
        container: Container::Big,
    };

    let sh_from_orig =
        SectionHeader::parse(base, header.e_shoff as usize, header.e_shnum as usize, ctx)
            .map_err(|_| "parse() section headers error")?;

    let sh_from_offset = SectionHeader::parse_from(
        &base[header.e_shoff as usize..],
        0,
        header.e_shnum as usize,
        ctx,
    )
    .map_err(|_| "parse_from() section headers error")?;

    if sh_from_orig == sh_from_offset {
        return Ok(true);
    }

    Err("Mismatching offset reading")
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
fn test_parse_from_text_section_size_lazy() {
    static ALIGNED_DATA: &AlignedData<[u8]> =
        &AlignedData(*include_bytes!("bins/elf/gnu_hash/hello.so"));
    assert_eq!(parse_from_text_section_size_lazy(&ALIGNED_DATA.0), Ok(true));
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

type SymverExpectation = std::collections::HashMap<&'static str, Vec<&'static str>>;

fn check_symver_expectations(
    bytes: &[u8],
    expect_versym: &Vec<u16>,
    expect_verneed: &SymverExpectation,
    expect_verdef: &SymverExpectation,
) -> Result<(), goblin::error::Error> {
    let elf = Elf::parse(bytes)?;

    if expect_versym.is_empty() {
        // We dont expect a symbol version section.
        assert!(elf.versym.is_none());
    } else {
        // We expect a symbol version section.
        assert!(elf.versym.is_some());

        let versym = elf.versym.as_ref().unwrap();
        check_symver_expectations_versym(versym, &elf.dynsyms, expect_versym);
    }

    if expect_verneed.is_empty() {
        // We dont expect a version definition section.
        assert!(elf.verneed.is_none());
    } else {
        // We expect a version definition section.
        assert!(elf.verneed.is_some());

        let verneed = elf.verneed.as_ref().unwrap();
        check_symver_expectations_verneed(verneed, expect_verneed, &elf.dynstrtab);
    }

    if expect_verdef.is_empty() {
        // We dont expect a version needed section.
        assert!(elf.verdef.is_none());
    } else {
        // We expect a version needed section.
        assert!(elf.verdef.is_some());

        let verdef = elf.verdef.as_ref().unwrap();
        check_symver_expectations_verdef(verdef, expect_verdef, &elf.dynstrtab);
    }

    Ok(())
}

fn check_symver_expectations_versym(
    versym: &VersymSection<'_>,
    dynsyms: &Symtab<'_>,
    expect_versym: &Vec<u16>,
) {
    // VERSYM section must contain one entry per DYNSYM.
    assert_eq!(dynsyms.len(), versym.len());

    // Check length computation + iteration count.
    assert_eq!(expect_versym.len(), versym.len());
    assert_eq!(expect_versym.len(), versym.iter().count());

    // Check symbol version identifier.
    for versym in versym.iter() {
        assert!(
            expect_versym.iter().any(|&expect| expect == versym.vs_val),
            "Unexpected SYMBOL VERSION index {}",
            versym.vs_val
        );
    }
}

fn check_symver_expectations_verneed(
    verneed: &VerneedSection<'_>,
    expect_verneed: &SymverExpectation,
    strtab: &Strtab<'_>,
) {
    // Resolve version strings.
    let verstr = |idx| strtab.get_at(idx).unwrap();

    // ELF file dependencies with version requirements.
    let need_files: Vec<_> = verneed.iter().collect();
    assert_eq!(
        expect_verneed.keys().len(),
        need_files.len(),
        "Expected different number of dependencies with version information!"
    );

    for need_file in &need_files {
        // Get file name of the dependency.
        let file_str = verstr(need_file.vn_file);

        // Check if we expect this dependency.
        let expect_vers = expect_verneed.get(&file_str);
        assert!(
            expect_vers.is_some(),
            "Unexpected FILE dependency {}!",
            file_str
        );
        let expect_vers = expect_vers.unwrap();

        // Version dependencies for this file dependency.
        let need_vers: Vec<_> = need_file.iter().collect();
        assert_eq!(
            expect_vers.len(),
            need_vers.len(),
            "Expected different number of version dependencies for {}!",
            file_str
        );

        for need_ver in &need_vers {
            // Get version string.
            let ver_str = verstr(need_ver.vna_name);

            // Check if we expect this version.
            assert!(
                expect_vers.iter().any(|&expect_ver| ver_str == expect_ver),
                "Unexpected VERSION dependency {}",
                ver_str
            );
        }
    }
}

fn check_symver_expectations_verdef(
    verdef: &VerdefSection<'_>,
    expect_verdef: &SymverExpectation,
    strtab: &Strtab<'_>,
) {
    // Resolve version strings.
    let verstr = |idx| strtab.get_at(idx).unwrap();

    // ELF version definitions.
    let defined_vers: Vec<_> = verdef.iter().collect();
    assert_eq!(
        expect_verdef.keys().len(),
        defined_vers.len(),
        "Expected different number of defined versions!"
    );

    for defined_ver in &defined_vers {
        // [0]   Defined version
        // [1..] Parent nodes
        let verdaux: Vec<_> = defined_ver.iter().collect();
        assert!(verdaux.len() >= 1);
        let version = &verdaux[0];
        let parents = &verdaux[1..];

        let version_str = verstr(version.vda_name);

        // Check if we expect this dependency.
        let expect_parents = expect_verdef.get(&version_str);
        assert!(
            expect_parents.is_some(),
            "Unexpected VERSION definition {}!",
            version_str
        );
        let expect_parents = expect_parents.unwrap();

        // Validate name of parent version nodes if we expect
        assert_eq!(
            expect_parents.len(),
            parents.len(),
            "Expected different number of parent nodes for {}!",
            version_str
        );

        for parent in parents {
            // Get parent string.
            let parent_str = verstr(parent.vda_name);

            // Check if we expect this parent.
            assert!(
                expect_parents
                    .iter()
                    .any(|&expect_parent| parent_str == expect_parent),
                "Unexpected PARENT node {}",
                parent_str
            );
        }
    }
}

#[rustfmt::skip]
#[test]
fn test_symver() -> Result<(), goblin::error::Error> {
    // NOTE: Expected Files & Symbol Versions depend on build system of the test ELF binaries.
    //       When rebuilding the referenced ELF file the version information must be checked and
    //       potentially updated:
    //       > readelf -V <elf>
    //
    // versym  - Vec<u16>
    //   value: symbol version identifier
    //
    // verneed - SymverExpectation
    //   keys : file dependencies
    //   value: vector of version dependencies for given file (key)
    //
    // verdef  - SymverExpectation
    //   keys : defined version nodes
    //   value: vector of parent nodes for given version node (key)

    // lib32 expectations

    let expect_lib32_versym : Vec<u16> = vec![
        0,0,4,5,
        0,0,3,0x8001,
        0x8002,2,3,
    ];

    let expect_lib32_verneed: SymverExpectation = [
        ("libc.so.6", vec!["GLIBC_2.0", "GLIBC_2.1.3"])
    ].iter().cloned().collect();

    let expect_lib32_verdef: SymverExpectation = [
        ("lib32.so", vec![]),
        ("v1", vec![]),
        ("v2", vec!["v1"]),
    ].iter().cloned().collect();

    // lib64 expectations

    let expect_lib64_versym :Vec<u16> = vec![
        0,0,4,0,
        0,4,3,0x8001,
        0x8002,2,3,
    ];

    let expect_lib64_verneed: SymverExpectation = [
        ("libc.so.6", vec!["GLIBC_2.2.5"])
    ].iter().cloned().collect();

    let expect_lib64_verdef: SymverExpectation = [
        ("lib64.so", vec![]),
        ("v1", vec![]),
        ("v2", vec!["v1"]),
    ].iter().cloned().collect();

    // prog32 expectations

    let expect_prog32_versym : Vec<u16> = vec![
        0,2,0,3,
        4,0,5,6,
        0,5,1,
    ];

    let expect_prog32_verneed: SymverExpectation = [
        ("libc.so.6", vec!["GLIBC_2.0", "GLIBC_2.1.3"]),
        ("libdl.so.2", vec!["GLIBC_2.0", "GLIBC_2.1"]),
        ("lib32.so", vec!["v2"]),
    ].iter().cloned().collect();

    let expect_prog32_verdef = SymverExpectation::new();

    // prog64 expectations

    let expect_prog64_versym : Vec<u16> = vec![
        0,2,0,3,
        3,4,0,0,
        4,3,
    ];

    let expect_prog64_verneed: SymverExpectation = [
        ("libdl.so.2", vec!["GLIBC_2.2.5"]),
        ("libc.so.6", vec!["GLIBC_2.2.5"]),
        ("lib64.so", vec!["v2"]),
    ].iter().cloned().collect();

    let expect_prog64_verdef = SymverExpectation::new();

    check_symver_expectations(include_bytes!("bins/elf/symver/lib32.so"), &expect_lib32_versym, &expect_lib32_verneed, &expect_lib32_verdef)?;
    check_symver_expectations(include_bytes!("bins/elf/symver/lib64.so"), &expect_lib64_versym, &expect_lib64_verneed, &expect_lib64_verdef)?;
    check_symver_expectations(include_bytes!("bins/elf/symver/prog32"), &expect_prog32_versym, &expect_prog32_verneed, &expect_prog32_verdef)?;
    check_symver_expectations(include_bytes!("bins/elf/symver/prog64"), &expect_prog64_versym, &expect_prog64_verneed, &expect_prog64_verdef)?;

    Ok(())
}
