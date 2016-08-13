pub use super::super::elf::section_header::*;

#[repr(C)]
#[derive(Clone, PartialEq, Default)]
#[cfg_attr(not(feature = "pure"), derive(Debug))]
pub struct SectionHeader {
  sh_name: u32,	// Section name (string tbl index)
  sh_type: u32,	// Section type
  sh_flags: u32, // Section flags
  sh_addr: u32,	// Section virtual addr at execution
  sh_offset: u32, // Section file offset
  sh_size: u32,	// Section size in bytes
  sh_link: u32,	// Link to another section
  sh_info: u32,	// Additional section information
  sh_addralign: u32, // Section alignment
  sh_entsize: u32, // Entry size if section holds table
}

pub const SIZEOF_SHDR: usize = 40;
