pub use super::super::elf::dyn::*;

#[derive(Copy, Clone, PartialEq)]
#[cfg_attr(not(feature = "pure"), derive(Debug))]
pub struct Dyn {
  pub d_tag: u32, // Dynamic entry type
  pub d_val: u32, // Integer value
}

pub const SIZEOF_DYN: usize = 8;
