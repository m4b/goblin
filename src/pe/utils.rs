use scroll::{Pread};
use alloc::string::ToString;
use error;

use super::section_table;

pub fn is_in_range (rva: usize, r1: usize, r2: usize) -> bool {
    r1 <= rva && rva < r2
}

#[inline] 
fn round_size(addr: usize, size: usize) -> usize {
    const PAGE_MASK: usize = 0xfff;
    (size + (addr & PAGE_MASK) + PAGE_MASK) & !PAGE_MASK
}

fn rva2offset (rva: usize, section: &section_table::SectionTable) -> usize {
    (rva - section.virtual_address as usize) + section.pointer_to_raw_data as usize
}

fn is_in_section (rva: usize, section: &section_table::SectionTable) -> bool {
    let section_size = 
        if section.virtual_size == 0 {
            round_size(0, section.size_of_raw_data as usize)
        } else {
            round_size(0, section.virtual_size as usize)
        };
    section.virtual_address as usize <= rva && rva < (section.virtual_address + section_size as u32) as usize
}

pub fn find_offset (rva: usize, sections: &[section_table::SectionTable]) -> Option<usize> {
    for (i, section) in sections.iter().enumerate() {
        debug!("Checking {} for {:#x} ∈ {:#x}..{:#x}", section.name().unwrap_or(""), rva, section.virtual_address, section.virtual_address + section.virtual_size);
        if is_in_section(rva, &section) {
            let offset = rva2offset(rva, &section);
            debug!("Found in section {}({}), remapped into offset {:#x}", section.name().unwrap_or(""), i, offset);
            return Some(offset)
        }
    }
    None
}

pub fn find_offset_or (rva: usize, sections: &[section_table::SectionTable], msg: &str) -> error::Result<usize> {
    find_offset(rva, sections).ok_or(error::Error::Malformed(msg.to_string()))
}

pub fn try_name<'a>(bytes: &'a [u8], rva: usize, sections: &[section_table::SectionTable]) -> error::Result<&'a str> {
    match find_offset(rva, sections) {
        Some(offset) => {
            Ok(bytes.pread::<&str>(offset)?)
        },
        None => {
            Err(error::Error::Malformed(format!("Cannot find name from rva {:#x} in sections: {:?}", rva, sections)))
        }
    }
}

macro_rules! parse_field_by_offset {
    ($bytes:ident, $sections:expr, $base_rva:expr, $offset:expr, $err_msg:expr) => {
        {
            let rva = $base_rva + $offset;
            let offset = utils::find_offset(rva, $sections).unwrap_or(rva);
            $bytes.pread_with(offset, LE)
                .map_err(|_| error::Error::Malformed(format!("{} (offset {:#x})", $err_msg, offset)))?
        }
    };
}

macro_rules! offset_of {
    ($struct_name:path, $field_name:ident) => ({
        // reference: memoffset crate and eddyb's implementation for offset_of!
        let ps = unsafe { &mem::uninitialized::<$struct_name>() };
        #[allow(unused_unsafe)]
        let pf = unsafe { &(*ps).$field_name };
        let o = (pf as *const _ as usize).wrapping_sub(ps as *const _ as usize);
        mem::forget(ps);
        o
    });
}

macro_rules! parse_field_by_name {
    ($bytes:ident, $sections:expr, $base_rva:expr, $struct_name:path, $field_name:ident, $err_msg:expr) => {
        {
            parse_field_by_offset!($bytes, $sections, $base_rva, offset_of!($struct_name, $field_name), $err_msg)
        }
    };
}

#[derive(Debug, Copy, Clone)]
pub struct CStructCtx<'a> {
    pub ptr: u32,
    pub sections: &'a [section_table::SectionTable],
}

macro_rules! implement_ctx_cstruct {
    (struct $name:ident {
        $($field_name:ident: $field_type:ty,)*
    }) => {
        #[derive(Debug, PartialEq, Copy, Clone, Default)]
        #[repr(C, packed)]
        pub struct $name {
            $(pub $field_name: $field_type,)*
        }

        impl<'a, 'b> ctx::TryFromCtx<'a, CStructCtx<'b>> for $name {
            type Error = error::Error;
            type Size = usize;
            #[inline]
            fn try_from_ctx(bytes: &'a [u8], CStructCtx { ptr, sections }: CStructCtx<'b>) -> Result<(Self, Self::Size), Self::Error> {
                let offset = ptr as usize;
                $(
                    let $field_name = parse_field_by_name!(bytes, sections, offset, $name, $field_name, format!("cannot parse {}::{}", stringify!($name), stringify!($field_name)));
                )*

                Ok(($name { $($field_name,)* }, mem::size_of::<$name>()))
            }
        }

        impl $name {
            pub fn parse(bytes: &[u8], offset: &mut usize, sections: &[section_table::SectionTable]) -> error::Result<Self> {
                let v = bytes.pread_with(0, CStructCtx { ptr: *offset as u32, sections });
                *offset += mem::size_of::<$name>();
                v
            }
        }
    };
}

