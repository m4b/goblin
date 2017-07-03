#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate goblin;

fuzz_target!(|data: &[u8]| {
    let _ = goblin::parse(data);
});
