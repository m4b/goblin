#[macro_use]
extern crate afl;

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(elf) = goblin::elf::Elf::parse(data) {
            for section_header in &elf.section_headers {
                let _ = elf.shdr_strtab.get_at(section_header.sh_name);
            }

            for _relocation in &elf.dynrels {}

            if let Some(mut it) = elf.iter_note_headers(data) {
                while let Some(Ok(_a)) = it.next() {}
            }

            if let Some(mut it) = elf.iter_note_sections(data, None) {
                while let Some(Ok(_a)) = it.next() {}
            }

            if let Some(mut it) = elf.iter_note_sections(data, Some("x")) {
                while let Some(Ok(_a)) = it.next() {}
            }
        }
    });
}
