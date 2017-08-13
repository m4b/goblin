extern crate goblin;
use std::process;

fn compare(args: Vec<&str>) {
    let apple = process::Command::new("/Library/Developer/CommandLineTools/usr/bin/dyldinfo")
        .args(&args)
        .output()
        .expect("run Apple dyldinfo");

    let goblin = process::Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--example")
        .arg("dyldinfo")
        .arg("--")
        .args(&args)
        .output()
        .expect("run cargo dyldinfo");

    if apple.stdout.as_slice() != goblin.stdout.as_slice() {
        eprintln!("dyldinfo calls disagree!");
        eprintln!("Apple dyldinfo {:?} output:\n{}", &args, String::from_utf8_lossy(&apple.stdout));
        eprintln!("---");
        eprintln!("cargo dyldinfo {:?} output:\n{}", &args, String::from_utf8_lossy(&goblin.stdout));
        panic!("Apple dyldinfo and cargo dyldinfo differed (args: {:?})", args);
    }
}

#[cfg(target_os="macos")]
#[test]
fn compare_binds() {
    compare(vec!["-bind", "/Library/Developer/CommandLineTools/usr/bin/dyldinfo"]);
    compare(vec!["-bind", "/Library/Developer/CommandLineTools/usr/bin/clang"]);
    compare(vec!["-bind", "/usr/bin/tmutil"]);
}

#[cfg(not(target_os="macos"))]
#[test]
fn skipped_on_this_platform() {
    // this test does nothing on other platforms
}
