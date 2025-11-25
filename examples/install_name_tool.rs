//! A simple install_name_tool clone using goblin's MachOWriter
//!
//! This tool supports a subset of install_name_tool operations:
//! - `-id <name>`: Change the install name of a dylib
//! - `-change <old> <new>`: Change a dylib dependency
//! - `-add_rpath <path>`: Add an rpath
//! - `-delete_rpath <path>`: Delete an rpath
//! - `-rpath <old> <new>`: Change an rpath

use goblin::mach::writer::modify_fat_binary;
use std::env;
use std::fs;
use std::process;

fn print_usage() {
    eprintln!("Usage: install_name_tool [options] <input_file>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -id <name>              Change the install name (LC_ID_DYLIB)");
    eprintln!("  -change <old> <new>     Change a dylib dependency");
    eprintln!("  -add_rpath <path>       Add an rpath");
    eprintln!("  -delete_rpath <path>    Delete an rpath");
    eprintln!("  -rpath <old> <new>      Change an rpath");
    eprintln!("  -o <output_file>        Write to output file (default: modify in place)");
    eprintln!();
    eprintln!("Multiple options can be combined in a single invocation.");
}

#[derive(Debug)]
enum Operation {
    ChangeId(String),
    ChangeDylib { old: String, new: String },
    AddRpath(String),
    DeleteRpath(String),
    ChangeRpath { old: String, new: String },
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let mut operations: Vec<Operation> = Vec::new();
    let mut input_file: Option<String> = None;
    let mut output_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-id" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: -id requires an argument");
                    process::exit(1);
                }
                operations.push(Operation::ChangeId(args[i + 1].clone()));
                i += 2;
            }
            "-change" => {
                if i + 2 >= args.len() {
                    eprintln!("Error: -change requires two arguments");
                    process::exit(1);
                }
                operations.push(Operation::ChangeDylib {
                    old: args[i + 1].clone(),
                    new: args[i + 2].clone(),
                });
                i += 3;
            }
            "-add_rpath" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: -add_rpath requires an argument");
                    process::exit(1);
                }
                operations.push(Operation::AddRpath(args[i + 1].clone()));
                i += 2;
            }
            "-delete_rpath" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: -delete_rpath requires an argument");
                    process::exit(1);
                }
                operations.push(Operation::DeleteRpath(args[i + 1].clone()));
                i += 2;
            }
            "-rpath" => {
                if i + 2 >= args.len() {
                    eprintln!("Error: -rpath requires two arguments");
                    process::exit(1);
                }
                operations.push(Operation::ChangeRpath {
                    old: args[i + 1].clone(),
                    new: args[i + 2].clone(),
                });
                i += 3;
            }
            "-o" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: -o requires an argument");
                    process::exit(1);
                }
                output_file = Some(args[i + 1].clone());
                i += 2;
            }
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            arg if arg.starts_with('-') => {
                eprintln!("Error: Unknown option: {}", arg);
                print_usage();
                process::exit(1);
            }
            _ => {
                if input_file.is_some() {
                    eprintln!("Error: Multiple input files specified");
                    process::exit(1);
                }
                input_file = Some(args[i].clone());
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
            eprintln!("Error reading '{}': {}", input_file, e);
            process::exit(1);
        }
    };

    // Apply operations
    let result = modify_fat_binary(data, |writer| {
        for op in &operations {
            match op {
                Operation::ChangeId(name) => {
                    writer.change_id(name)?;
                }
                Operation::ChangeDylib { old, new } => {
                    writer.change_dylib(old, new)?;
                }
                Operation::AddRpath(path) => {
                    writer.add_rpath(path)?;
                }
                Operation::DeleteRpath(path) => {
                    writer.delete_rpath(path)?;
                }
                Operation::ChangeRpath { old, new } => {
                    writer.change_rpath(old, new)?;
                }
            }
        }
        Ok(())
    });

    let modified = match result {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error modifying binary: {}", e);
            process::exit(1);
        }
    };

    // Write output
    let output_path = output_file.as_ref().unwrap_or(&input_file);
    if let Err(e) = fs::write(output_path, &modified) {
        eprintln!("Error writing '{}': {}", output_path, e);
        process::exit(1);
    }
}
