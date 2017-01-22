use pe::error::*;
use scroll;

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub const SIZEOF_DATA_DIRECTORY: usize = 8;

impl DataDirectory {
    pub fn parse<B: scroll::Gread>(bytes: &B, offset: &mut usize) -> Result<Self> {
        Ok (DataDirectory { virtual_address: bytes.gread(offset, scroll::LE)?, size: bytes.gread(offset, scroll::LE)? })
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct DataDirectories {
    pub data_directories: [Option<DataDirectory>; 16],
}

impl DataDirectories {
    pub fn parse<B: scroll::Gread>(bytes: &B, count: usize, offset: &mut usize) -> Result<Self> {
        let mut data_directories = [None; 16];
        for i in 0..count {
            data_directories[i] = Some(DataDirectory::parse(bytes, offset)?);
        }
        Ok (DataDirectories { data_directories: data_directories })
    }
    pub fn get_export_table(&self) -> &Option<DataDirectory> {
        let idx = 0;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_import_table(&self) -> &Option<DataDirectory> {
        let idx = 1;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_resource_table(&self) ->          &Option<DataDirectory> {
        let idx = 2;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_exception_table(&self) ->         &Option<DataDirectory> {
        let idx = 3;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_certificate_table(&self) ->       &Option<DataDirectory> {
        let idx = 4;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_base_relocation_table(&self) ->   &Option<DataDirectory> {
        let idx = 5;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_debug_table(&self) ->             &Option<DataDirectory> {
        let idx = 6;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_architecture(&self) ->            &Option<DataDirectory> {
        let idx = 7;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_global_ptr(&self) ->              &Option<DataDirectory> {
        let idx = 8;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_tls_table(&self) ->               &Option<DataDirectory> {
        let idx = 9;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_load_config_table(&self) ->       &Option<DataDirectory> {
        let idx = 10;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_bound_import_table(&self) ->      &Option<DataDirectory> {
        let idx = 11;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_import_address_table(&self) ->    &Option<DataDirectory> {
        let idx = 12;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_delay_import_descriptor(&self) -> &Option<DataDirectory> {
        let idx = 13;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
    pub fn get_clr_runtime_header(&self) ->      &Option<DataDirectory> {
        let idx = 14;
        unsafe { self.data_directories.get_unchecked(idx) }
    }
}

/*

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct DataDirectories {
    pub data_directories: Vec<DataDirectory>,
}

impl DataDirectories {
    pub fn parse<B: scroll::Gread>(bytes: &B, count: usize, offset: &mut usize) -> Result<Self> {
        let mut data_directories = Vec::with_capacity(count);
        for _ in 0..count {
            data_directories.push(DataDirectory::parse(bytes, offset)?)
        }
        Ok (DataDirectories { data_directories: data_directories })
    }
    pub fn get_export_table(&self) ->            Option<&DataDirectory> {
        let idx = 0;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_import_table(&self) ->            Option<&DataDirectory> {
        let idx = 1;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_resource_table(&self) ->          Option<&DataDirectory> {
        let idx = 2;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_exception_table(&self) ->         Option<&DataDirectory> {
        let idx = 3;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_certificate_table(&self) ->       Option<&DataDirectory> {
        let idx = 4;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_base_relocation_table(&self) ->   Option<&DataDirectory> {
        let idx = 5;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_debug_table(&self) ->             Option<&DataDirectory> {
        let idx = 6;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_architecture(&self) ->            Option<&DataDirectory> {
        let idx = 7;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_global_ptr(&self) ->              Option<&DataDirectory> {
        let idx = 8;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_tls_table(&self) ->               Option<&DataDirectory> {
        let idx = 9;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_load_config_table(&self) ->       Option<&DataDirectory> {
        let idx = 10;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_bound_import_table(&self) ->      Option<&DataDirectory> {
        let idx = 11;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_import_address_table(&self) ->    Option<&DataDirectory> {
        let idx = 12;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_delay_import_descriptor(&self) -> Option<&DataDirectory> {
        let idx = 13;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
    pub fn get_clr_runtime_header(&self) ->      Option<&DataDirectory> {
        let idx = 14;
        if self.data_directories.len() > idx {
            Some (unsafe { self.data_directories.get_unchecked(idx) })
        } else {
            None
        }
    }
}
*/
