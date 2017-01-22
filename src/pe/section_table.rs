use pe::error::*;
use scroll;

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct SectionTable {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

pub const SIZEOF_SECTION_TABLE: usize = 8 * 5;

impl SectionTable {
    pub fn parse<B: scroll::Gread> (bytes: &B, offset: &mut usize) -> Result<Self> {
        let mut table = SectionTable::default();
        let mut name = [0u8; 8];
        for i in 0..8 {
            name[i] = bytes.gread(offset, scroll::LE)?;
        }
        table.name = name;
        table.virtual_size = bytes.gread(offset, scroll::LE)?;
        table.virtual_address = bytes.gread(offset, scroll::LE)?;
        table.size_of_raw_data = bytes.gread(offset, scroll::LE)?;
        table.pointer_to_raw_data = bytes.gread(offset, scroll::LE)?;
        table.pointer_to_relocations = bytes.gread(offset, scroll::LE)?;
        table.pointer_to_linenumbers = bytes.gread(offset, scroll::LE)?;
        table.number_of_relocations = bytes.gread(offset, scroll::LE)?;
        table.number_of_linenumbers = bytes.gread(offset, scroll::LE)?;
        table.characteristics = bytes.gread(offset, scroll::LE)?;
        Ok(table)
    }
}

/*
let get binary (header:PEHeader.t) =
  let offset =
    header.dos_header.pe_pointer + PEHeader.sizeof_coff_header
    + header.coff_header.size_of_optional_header
  in
  let nsections = header.coff_header.number_of_sections in
  let rec loop acc count =
    if (count >= nsections) then
      List.rev acc
    else
      let o = offset + (count * sizeof_section_table) in
      let st = get_section_table binary o in
      loop (st::acc) (count+1)
  in loop [] 0
*/
