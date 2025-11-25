//! A drop-in replacement for `patchelf` using goblin
//!
//! This tool can modify ELF binaries to:
//! - Set the dynamic linker/interpreter (--set-interpreter)
//! - Set RPATH (--set-rpath)
//! - Set RUNPATH (--set-runpath)
//! - Add RPATH (--add-rpath) - kept for compatibility
//! - Set SONAME (--set-soname)
//! - Add needed libraries (--add-needed)
//! - Remove RPATH (--remove-rpath)
//! - Remove RUNPATH (--remove-runpath)
//!
//! Usage examples:
//!   patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 executable
//!   patchelf --set-rpath /usr/local/lib:/opt/lib executable
//!   patchelf --set-runpath '$ORIGIN/../lib' executable
//!   patchelf --add-needed libfoo.so executable
//!   patchelf --set-soname libnew.so.1 library.so

use goblin::elf::writer::ElfWriter;
use std::env;
use std::fs;
use std::process;

fn print_usage() {
    eprintln!("Usage: patchelf [options] <input_file>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --set-interpreter <path>      Set the dynamic linker/interpreter");
    eprintln!("  --set-rpath <paths>            Set RPATH (colon-separated paths)");
    eprintln!("  --set-runpath <paths>          Set RUNPATH (colon-separated paths)");
    eprintln!("  --add-rpath <path>             Alias for --set-rpath");
    eprintln!("  --set-soname <name>            Set SONAME for shared library");
    eprintln!("  --add-needed <library>         Add a needed library dependency");
    eprintln!("  --remove-rpath                 Remove RPATH");
    eprintln!("  --remove-runpath               Remove RUNPATH");
    eprintln!("  --output <file>                Specify output file (default: in-place)");
    eprintln!();
    eprintln!("Multiple operations can be combined in a single invocation.");
}

enum Operation {
    SetInterpreter(String),
    SetRpath(String),
    SetRunpath(String),
    SetSoname(String),
    AddNeeded(String),
    RemoveRpath,
    RemoveRunpath,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        print_usage();
        process::exit(1);
    }

    let mut operations = Vec::new();
    let mut output_file: Option<String> = None;
    let mut input_file: Option<String> = None;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--set-interpreter" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --set-interpreter requires an argument");
                    process::exit(1);
                }
                operations.push(Operation::SetInterpreter(args[i + 1].clone()));
                i += 2;
            }
            "--set-rpath" | "--add-rpath" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: {} requires an argument", args[i]);
                    process::exit(1);
                }
                operations.push(Operation::SetRpath(args[i + 1].clone()));
                i += 2;
            }
            "--set-runpath" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --set-runpath requires an argument");
                    process::exit(1);
                }
                operations.push(Operation::SetRunpath(args[i + 1].clone()));
                i += 2;
            }
            "--set-soname" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --set-soname requires an argument");
                    process::exit(1);
                }
                operations.push(Operation::SetSoname(args[i + 1].clone()));
                i += 2;
            }
            "--add-needed" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --add-needed requires an argument");
                    process::exit(1);
                }
                operations.push(Operation::AddNeeded(args[i + 1].clone()));
                i += 2;
            }
            "--remove-rpath" => {
                operations.push(Operation::RemoveRpath);
                i += 1;
            }
            "--remove-runpath" => {
                operations.push(Operation::RemoveRunpath);
                i += 1;
            }
            "--output" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --output requires an argument");
                    process::exit(1);
                }
                output_file = Some(args[i + 1].clone());
                i += 2;
            }
            arg => {
                if arg.starts_with("--") {
                    eprintln!("Error: Unknown option: {}", arg);
                    print_usage();
                    process::exit(1);
                }
                if input_file.is_some() {
                    eprintln!("Error: Multiple input files specified");
                    process::exit(1);
                }
                input_file = Some(arg.to_string());
                i += 1;
            }
        }
    }

    let input_file = match input_file {
        Some(f) => f,
        None => {
            eprintln!("Error: No input file specified");
            print_usage();
            process::exit(1);
        }
    };

    if operations.is_empty() {
        eprintln!("Error: No operations specified");
        print_usage();
        process::exit(1);
    }

    // Read the input file
    let data = match fs::read(&input_file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading input file '{}': {}", input_file, e);
            process::exit(1);
        }
    };

    // Create writer and apply operations
    let mut writer = match ElfWriter::new(data) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Error parsing ELF file: {}", e);
            process::exit(1);
        }
    };

    for op in &operations {
        let result = match op {
            Operation::SetInterpreter(path) => writer.set_interpreter(path),
            Operation::SetRpath(paths) => writer.set_rpath(paths),
            Operation::SetRunpath(paths) => writer.set_runpath(paths),
            Operation::SetSoname(name) => writer.set_soname(name),
            Operation::AddNeeded(lib) => writer.add_needed(lib),
            Operation::RemoveRpath => writer.remove_rpath(),
            Operation::RemoveRunpath => writer.remove_runpath(),
        };

        if let Err(e) = result {
            eprintln!("Error applying operation: {}", e);
            process::exit(1);
        }
    }

    // Build the modified binary
    let modified_data = match writer.build() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error building modified binary: {}", e);
            process::exit(1);
        }
    };

    // Write output
    let output_path = output_file.unwrap_or_else(|| input_file.clone());

    // Write to a temporary file first, then rename (atomic operation)
    let temp_output = format!("{}.tmp", output_path);
    if let Err(e) = fs::write(&temp_output, &modified_data) {
        eprintln!("Error writing output file '{}': {}", temp_output, e);
        process::exit(1);
    }

    if let Err(e) = fs::rename(&temp_output, &output_path) {
        eprintln!("Error renaming temporary file: {}", e);
        let _ = fs::remove_file(&temp_output);
        process::exit(1);
    }

    println!("Successfully modified: {}", output_path);
}
