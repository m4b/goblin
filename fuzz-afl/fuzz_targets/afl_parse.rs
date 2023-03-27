#[macro_use]
extern crate afl;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = goblin::Object::parse(data);
    });
}
