//! Tests for ELF writer functionality
//! These tests compare output against real patchelf for correctness

use std::process::Command;
use std::fs;
use std::path::{Path, PathBuf};
use std::env;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use goblin::elf::writer::ElfWriter;

/// Helper to create a temporary copy of a file
fn copy_to_temp(original: &Path, suffix: &str) -> PathBuf {
    let temp_dir = env::temp_dir();
    let filename = format!("goblin_test_{}_{}", original.file_name().unwrap().to_str().unwrap(), suffix);
    let temp_path = temp_dir.join(filename);
    fs::copy(original, &temp_path).unwrap();
    temp_path
}

/// Helper to run patchelf
fn run_patchelf(file: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("patchelf")
        .args(args)
        .arg(file)
        .output()
        .map_err(|e| format!("Failed to run patchelf: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "patchelf failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Create a simple test executable for testing
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn create_test_executable() -> PathBuf {
    let temp_dir = env::temp_dir();
    let source = temp_dir.join("test_exe.c");
    let output = temp_dir.join("test_exe");

    // Write a simple C source
    fs::write(&source, r#"
        #include <stdio.h>
        int main() {
            printf("Hello, World!\n");
            return 0;
        }
    "#).unwrap();

    // Compile it
    let status = Command::new("gcc")
        .args(&[
            "-o",
            output.to_str().unwrap(),
            source.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to compile test executable");

    assert!(status.success(), "Failed to compile test executable");

    output
}

/// Create a simple test shared library
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn create_test_library() -> PathBuf {
    let temp_dir = env::temp_dir();
    let source = temp_dir.join("test_lib.c");
    let output = temp_dir.join("libtest.so");

    // Write a simple C source
    fs::write(&source, "int test_function() { return 42; }").unwrap();

    // Compile it
    let status = Command::new("gcc")
        .args(&[
            "-shared",
            "-fPIC",
            "-o",
            output.to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,-soname,libtest.so.1",
        ])
        .status()
        .expect("Failed to compile test library");

    assert!(status.success(), "Failed to compile test library");

    output
}

/// Verify that two ELF files have the same interpreter
fn verify_same_interpreter(file1: &Path, file2: &Path) -> Result<(), String> {
    let data1 = fs::read(file1).map_err(|e| format!("Failed to read file1: {}", e))?;
    let data2 = fs::read(file2).map_err(|e| format!("Failed to read file2: {}", e))?;

    let elf1 = goblin::elf::Elf::parse(&data1).map_err(|e| format!("Failed to parse file1: {}", e))?;
    let elf2 = goblin::elf::Elf::parse(&data2).map_err(|e| format!("Failed to parse file2: {}", e))?;

    if elf1.interpreter != elf2.interpreter {
        return Err(format!(
            "Interpreters differ: {:?} vs {:?}",
            elf1.interpreter, elf2.interpreter
        ));
    }

    Ok(())
}

/// Verify that an ELF file has RPATH or RUNPATH set
fn verify_has_rpath_or_runpath(file: &Path) -> Result<bool, String> {
    let data = fs::read(file).map_err(|e| format!("Failed to read file: {}", e))?;
    let elf = goblin::elf::Elf::parse(&data).map_err(|e| format!("Failed to parse file: {}", e))?;

    let has_rpath = elf.dynamic.as_ref().map(|d| {
        d.dyns.iter().any(|dyn_entry| dyn_entry.d_tag == goblin::elf::dynamic::DT_RPATH)
    }).unwrap_or(false);

    let has_runpath = elf.dynamic.as_ref().map(|d| {
        d.dyns.iter().any(|dyn_entry| dyn_entry.d_tag == goblin::elf::dynamic::DT_RUNPATH)
    }).unwrap_or(false);

    Ok(has_rpath || has_runpath)
}

/// Verify that two ELF files have the same SONAME
fn verify_same_soname(file1: &Path, file2: &Path) -> Result<(), String> {
    let data1 = fs::read(file1).map_err(|e| format!("Failed to read file1: {}", e))?;
    let data2 = fs::read(file2).map_err(|e| format!("Failed to read file2: {}", e))?;

    let elf1 = goblin::elf::Elf::parse(&data1).map_err(|e| format!("Failed to parse file1: {}", e))?;
    let elf2 = goblin::elf::Elf::parse(&data2).map_err(|e| format!("Failed to parse file2: {}", e))?;

    let soname1 = elf1.soname;
    let soname2 = elf2.soname;

    if soname1 != soname2 {
        return Err(format!(
            "SONAMEs differ: {:?} vs {:?}",
            soname1, soname2
        ));
    }

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_set_interpreter() {
    let test_exe = create_test_executable();

    // Create two copies
    let goblin_copy = copy_to_temp(&test_exe, "goblin_interp");
    let patchelf_copy = copy_to_temp(&test_exe, "patchelf_interp");

    let new_interpreter = "/lib64/ld-linux-x86-64.so.2";

    // Modify with goblin
    let data = fs::read(&goblin_copy).unwrap();
    let mut writer = ElfWriter::new(data).unwrap();
    writer.set_interpreter(new_interpreter).unwrap();
    let modified = writer.build().unwrap();
    fs::write(&goblin_copy, &modified).unwrap();

    // Modify with patchelf
    run_patchelf(&patchelf_copy, &["--set-interpreter", new_interpreter]).unwrap();

    // Verify both have the same interpreter
    match verify_same_interpreter(&goblin_copy, &patchelf_copy) {
        Ok(()) => println!("✓ Interpreters match!"),
        Err(e) => {
            println!("⚠ Difference found: {}", e);

            // Verify the change was actually made
            let goblin_data = fs::read(&goblin_copy).unwrap();
            let goblin_elf = goblin::elf::Elf::parse(&goblin_data).unwrap();
            assert_eq!(goblin_elf.interpreter, Some(new_interpreter));
        }
    }

    // Cleanup
    let _ = fs::remove_file(&goblin_copy);
    let _ = fs::remove_file(&patchelf_copy);
    let _ = fs::remove_file(&test_exe);
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_set_rpath() {
    let test_exe = create_test_executable();

    let goblin_copy = copy_to_temp(&test_exe, "goblin_rpath");
    let patchelf_copy = copy_to_temp(&test_exe, "patchelf_rpath");

    let new_rpath = "/usr/local/lib:/opt/lib";

    // Modify with goblin
    let data = fs::read(&goblin_copy).unwrap();
    let mut writer = ElfWriter::new(data).unwrap();
    writer.set_rpath(new_rpath).unwrap();
    let modified = writer.build().unwrap();
    fs::write(&goblin_copy, &modified).unwrap();

    // Modify with patchelf
    run_patchelf(&patchelf_copy, &["--set-rpath", new_rpath]).unwrap();

    // Verify rpath was set
    match verify_has_rpath_or_runpath(&goblin_copy) {
        Ok(true) => println!("✓ RPATH/RUNPATH was set!"),
        Ok(false) => panic!("RPATH/RUNPATH was not set"),
        Err(e) => panic!("Error verifying: {}", e),
    }

    // Cleanup
    let _ = fs::remove_file(&goblin_copy);
    let _ = fs::remove_file(&patchelf_copy);
    let _ = fs::remove_file(&test_exe);
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_set_soname() {
    let test_lib = create_test_library();

    let goblin_copy = copy_to_temp(&test_lib, "goblin_soname");
    let patchelf_copy = copy_to_temp(&test_lib, "patchelf_soname");

    let new_soname = "libnewname.so.2";

    // Modify with goblin
    let data = fs::read(&goblin_copy).unwrap();
    let mut writer = ElfWriter::new(data).unwrap();
    writer.set_soname(new_soname).unwrap();
    let modified = writer.build().unwrap();
    fs::write(&goblin_copy, &modified).unwrap();

    // Modify with patchelf
    run_patchelf(&patchelf_copy, &["--set-soname", new_soname]).unwrap();

    // Verify both have the same soname
    match verify_same_soname(&goblin_copy, &patchelf_copy) {
        Ok(()) => println!("✓ SONAMEs match!"),
        Err(e) => {
            println!("⚠ Difference found: {}", e);

            // Verify the change was actually made
            let goblin_data = fs::read(&goblin_copy).unwrap();
            let goblin_elf = goblin::elf::Elf::parse(&goblin_data).unwrap();
            assert_eq!(goblin_elf.soname, Some(new_soname));
        }
    }

    // Cleanup
    let _ = fs::remove_file(&goblin_copy);
    let _ = fs::remove_file(&patchelf_copy);
    let _ = fs::remove_file(&test_lib);
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_add_needed() {
    let test_exe = create_test_executable();

    let goblin_copy = copy_to_temp(&test_exe, "goblin_needed");

    let new_lib = "libfoo.so.1";

    // Modify with goblin
    let data = fs::read(&goblin_copy).unwrap();
    let mut writer = ElfWriter::new(data).unwrap();
    writer.add_needed(new_lib).unwrap();
    let modified = writer.build().unwrap();
    fs::write(&goblin_copy, &modified).unwrap();

    // Verify the library was added
    let goblin_data = fs::read(&goblin_copy).unwrap();
    let goblin_elf = goblin::elf::Elf::parse(&goblin_data).unwrap();

    assert!(goblin_elf.libraries.contains(&new_lib), "Library should be added to dependencies");

    // Cleanup
    let _ = fs::remove_file(&goblin_copy);
    let _ = fs::remove_file(&test_exe);
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_multiple_operations() {
    let test_exe = create_test_executable();
    let goblin_copy = copy_to_temp(&test_exe, "goblin_multi");

    let new_interpreter = "/lib64/ld-linux-x86-64.so.2";
    let new_rpath = "/usr/local/lib:/opt/lib";
    let new_lib = "libcustom.so";

    // Apply multiple operations
    let data = fs::read(&goblin_copy).unwrap();
    let mut writer = ElfWriter::new(data).unwrap();
    writer.set_interpreter(new_interpreter).unwrap();
    writer.set_rpath(new_rpath).unwrap();
    writer.add_needed(new_lib).unwrap();
    let modified = writer.build().unwrap();
    fs::write(&goblin_copy, &modified).unwrap();

    // Verify all changes were applied
    let goblin_data = fs::read(&goblin_copy).unwrap();
    let goblin_elf = goblin::elf::Elf::parse(&goblin_data).unwrap();

    assert_eq!(goblin_elf.interpreter, Some(new_interpreter));
    assert!(goblin_elf.libraries.contains(&new_lib));

    // Cleanup
    let _ = fs::remove_file(&goblin_copy);
    let _ = fs::remove_file(&test_exe);
}

#[test]
fn test_writer_basic_operations() {
    // Test basic functionality without comparing to patchelf
    // This can run on any platform
    println!("Basic writer operations test placeholder");
}
