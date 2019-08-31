use crate::error;
use scroll::{Pread, Pwrite, SizeWith};

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
#[derive(Pread, Pwrite, SizeWith)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub const SIZEOF_DATA_DIRECTORY: usize = 8;
const NUM_DATA_DIRECTORIES: usize = 16;

impl DataDirectory {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        let dd = bytes.gread_with(offset, scroll::LE)?;
        Ok (dd)
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct DataDirectories {
    pub data_directories: [Option<DataDirectory>; NUM_DATA_DIRECTORIES],
}

macro_rules! make_DataDirectory_getters {(
    $(
        $name:ident => $idx:literal;
    )*
) => (
    $(
        #[inline]
        pub
        fn $name (self: &'_ Self)
            -> &'_ Option<DataDirectory>
        {
            const INDEX: usize = $idx;
            unsafe {
                // # Safety
                //
                //   - Indexing is checked at compile-time
                let _: [_; NUM_DATA_DIRECTORIES] =
                    self.data_directories
                ;
                const_assert!(INDEX < NUM_DATA_DIRECTORIES);
                self.data_directories.get_unchecked(INDEX)
            }
        }
    )*
)}

impl DataDirectories {
    pub fn parse(bytes: &[u8], count: usize, offset: &mut usize) -> error::Result<Self> {
        let mut data_directories = [None; NUM_DATA_DIRECTORIES];
        if count > NUM_DATA_DIRECTORIES { return Err (error::Error::Malformed(format!("data directory count ({}) is greater than maximum number of data directories ({})", count, NUM_DATA_DIRECTORIES))) }
        for dir in data_directories.iter_mut().take(count) {
            let dd = DataDirectory::parse(bytes, offset)?;
            let dd = if dd.virtual_address == 0 && dd.size == 0 { None } else { Some (dd) };
            *dir = dd;
        }
        Ok (DataDirectories { data_directories })
    }
    make_DataDirectory_getters! {
        get_export_table            =>  0;
        get_import_table            =>  1;
        get_resource_table          =>  2;
        get_exception_table         =>  3;
        get_certificate_table       =>  4;
        get_base_relocation_table   =>  5;
        get_debug_table             =>  6;
        get_architecture            =>  7;
        get_global_ptr              =>  8;
        get_tls_table               =>  9;
        get_load_config_table       => 10;
        get_bound_import_table      => 11;
        get_import_address_table    => 12;
        get_delay_import_descriptor => 13;
        get_clr_runtime_header      => 14;
    }
}
