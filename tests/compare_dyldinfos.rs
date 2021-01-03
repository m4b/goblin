use std::process;

fn get_realpath(cmd: &str) -> String {
    let output = process::Command::new("/usr/bin/xcrun")
        .arg("-f")
        .arg(cmd)
        .output()
        .expect("can get realpath");
    String::from_utf8(output.stdout).expect("output is valid utf8")
}

pub fn compare(args: Vec<&str>) {
    let apple = process::Command::new("/usr/bin/xcrun")
        .arg("dyldinfo")
        .arg("-arch")
        .arg("x86_64")
        .args(&args)
        .output()
        .expect("run Apple dyldinfo");

    let goblin = process::Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--example")
        .arg("dyldinfo")
        .arg("--")
        .arg("-arch")
        .arg("x86_64")
        .args(&args)
        .output()
        .expect("run cargo dyldinfo");

    if apple.stdout.as_slice() != goblin.stdout.as_slice() {
        println!("dyldinfo calls disagree!");
        println!(
            "Apple dyldinfo {:?} output:\n{}",
            &args,
            String::from_utf8_lossy(&apple.stdout)
        );
        println!("---");
        println!(
            "cargo dyldinfo {:?} output:\n{}",
            &args,
            String::from_utf8_lossy(&goblin.stdout)
        );
        panic!(
            "Apple dyldinfo and cargo dyldinfo differed (args: {:?})",
            args
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn compare_binds() {
    let dyldinfo = get_realpath("dyldinfo");
    let clang = get_realpath("clang");
    compare(vec!["-bind", &dyldinfo]);
    compare(vec!["-bind", &clang]);
    compare(vec!["-bind", "/usr/bin/tmutil"]);
}

#[cfg(target_os = "macos")]
#[test]
fn compare_lazy_binds() {
    let dyldinfo = get_realpath("dyldinfo");
    let clang = get_realpath("clang");
    compare(vec!["-lazy_bind", &dyldinfo]);
    compare(vec!["-lazy_bind", &clang]);
    compare(vec!["-lazy_bind", "/usr/bin/tmutil"]);
}

#[cfg(target_os = "macos")]
#[test]
fn compare_combined_options() {
    let dyldinfo = get_realpath("dyldinfo");
    compare(vec!["-lazy_bind", "-bind", &dyldinfo]);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn skipped_on_this_platform() {
    // this test does nothing on other platforms
}
