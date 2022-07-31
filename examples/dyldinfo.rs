use goblin::mach;
use goblin::mach::SingleArch;
use std::borrow::Cow;
use std::env;
use std::fs;
use std::path::Path;
use std::process;

fn usage() -> ! {
    println!("usage: dyldinfo <options> <mach-o file>");
    println!(
        "   [-arch <arch>]     the architecture to print binds for, only applies for fat binaries"
    );
    println!("    -bind             print binds as seen by macho::imports()");
    println!("    -lazy_bind        print lazy binds as seen by macho::imports()");
    process::exit(1);
}

fn name_to_str(name: &[u8; 16]) -> Cow<'_, str> {
    for i in 0..16 {
        if name[i] == 0 {
            return String::from_utf8_lossy(&name[0..i]);
        }
    }
    String::from_utf8_lossy(&name[..])
}

fn dylib_name(name: &str) -> &str {
    // observed behavior:
    //   "/usr/lib/libc++.1.dylib" => "libc++"
    //   "/usr/lib/libSystem.B.dylib" => "libSystem"
    //   "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" => "CoreFoundation"
    name.rsplit('/').next().unwrap().split('.').next().unwrap()
}

fn print_binds(sections: &[mach::segment::Section], imports: &[mach::imports::Import]) {
    println!("bind information:");

    println!(
        "{:7} {:16} {:14} {:7} {:6} {:16} symbol",
        "segment", "section", "address", "type", "addend", "dylib",
    );

    for import in imports.iter().filter(|i| !i.is_lazy) {
        // find the section that imported this symbol
        let section = sections
            .iter()
            .find(|s| import.address >= s.addr && import.address < (s.addr + s.size));

        // get &strs for its name
        let (segname, sectname) = section
            .map(|sect| (name_to_str(&sect.segname), name_to_str(&sect.sectname)))
            .unwrap_or((Cow::Borrowed("?"), Cow::Borrowed("?")));

        println!(
            "{:7} {:16} 0x{:<12X} {:7} {:6} {:16} {}{}",
            segname,
            sectname,
            import.address,
            "pointer",
            import.addend,
            dylib_name(import.dylib),
            import.name,
            if import.is_weak { " (weak import)" } else { "" }
        );
    }
}

fn print_lazy_binds(sections: &[mach::segment::Section], imports: &[mach::imports::Import]) {
    println!("lazy binding information (from lazy_bind part of dyld info):");

    println!(
        "{:7} {:16} {:10} {:6} {:16} symbol",
        "segment", "section", "address", "index", "dylib",
    );

    for import in imports.iter().filter(|i| i.is_lazy) {
        // find the section that imported this symbol
        let section = sections
            .iter()
            .find(|s| import.address >= s.addr && import.address < (s.addr + s.size));

        // get &strs for its name
        let (segname, sectname) = section
            .map(|sect| (name_to_str(&sect.segname), name_to_str(&sect.sectname)))
            .unwrap_or((Cow::Borrowed("?"), Cow::Borrowed("?")));

        println!(
            "{:7} {:16} 0x{:<8X} {:<06} {:16} {}",
            segname,
            sectname,
            import.address,
            format!("0x{:04X}", import.start_of_sequence_offset),
            dylib_name(import.dylib),
            import.name
        );
    }
}

fn print(macho: &mach::MachO, bind: bool, lazy_bind: bool) {
    // collect sections and sort by address
    let mut sections: Vec<mach::segment::Section> = Vec::new();
    for sects in macho.segments.sections() {
        sections.extend(sects.map(|r| r.expect("section").0));
    }
    sections.sort_by_key(|s| s.addr);

    // get the imports
    let imports = macho.imports().expect("imports");

    if bind {
        print_binds(&sections, &imports);
    }
    if lazy_bind {
        print_lazy_binds(&sections, &imports);
    }
}

fn print_multi_arch(
    multi_arch: &mach::MultiArch,
    arch: Option<String>,
    bind: bool,
    lazy_bind: bool,
) {
    if let Some(arch) = arch {
        if let Some((cputype, _)) = mach::constants::cputype::get_arch_from_flag(&arch) {
            for bin in multi_arch.into_iter() {
                match bin {
                    Ok(SingleArch::MachO(bin)) => {
                        if bin.header.cputype == cputype {
                            print(&bin, bind, lazy_bind);
                            process::exit(0);
                        }
                    }
                    Ok(SingleArch::Archive(_)) => {
                        // dyld_info doesn't seem to handle archives
                        // in fat binaries, so neither do we.
                        println!("Does not contain specified arches");
                        process::exit(1);
                    }
                    Err(err) => {
                        println!("err: {:?}", err);
                        process::exit(1);
                    }
                }
            }

            println!("err: no slice found for -arch {:?}", arch);
            process::exit(1);
        } else {
            println!("err: invalid -arch {:?}", arch);
            process::exit(1);
        }
    } else {
        println!("err: -arch is required for fat binaries");
        process::exit(1);
    }
}

fn main() {
    let len = env::args().len();

    let mut bind = false;
    let mut lazy_bind = false;
    let mut next_arch = false;
    let mut arch = None;

    if len <= 2 {
        usage();
    } else {
        // parse flags
        {
            let mut flags = env::args().collect::<Vec<_>>();
            flags.pop();
            flags.remove(0);
            for option in flags {
                if next_arch {
                    next_arch = false;
                    arch = Some(option);
                    continue;
                }
                match option.as_str() {
                    "-arch" => next_arch = true,
                    "-bind" => bind = true,
                    "-lazy_bind" => lazy_bind = true,
                    other => {
                        println!("unknown flag: {}", other);
                        println!();
                        usage();
                    }
                }
            }
        }

        // open the file
        let path = env::args_os().last().unwrap();
        let path = Path::new(&path);
        let buffer = fs::read(&path).unwrap();
        match mach::Mach::parse(&buffer) {
            Ok(macho) => match macho {
                mach::Mach::Fat(bin) => {
                    print_multi_arch(&bin, arch, bind, lazy_bind);
                }
                mach::Mach::Binary(bin) => {
                    print(&bin, bind, lazy_bind);
                }
            },
            Err(err) => {
                println!("err: {:?}", err);
                process::exit(2);
            }
        }
    }
}
