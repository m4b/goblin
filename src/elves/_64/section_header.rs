#[repr(C)]
pub struct SectionHeader {
    pub sh_name: u64,
    pub sh_type: u64,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u64,
    pub sh_info: u64,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}
