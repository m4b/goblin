//! A Mach-o fat binary is a multi-architecture binary container

use std::fmt;
use std::fs::File;
use std::io::{self, Read};

use scroll::{self, Gread};
use super::constants::cputype;
use error;

pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_CIGAM: u32 = 0xbebafeca;

#[repr(C)]
#[derive(Clone, Copy, Default)]
/// The Mach-o `FatHeader` always has its data bigendian
pub struct FatHeader {
    pub magic: u32,
    pub nfat_arch: u32,
}

pub const SIZEOF_FAT_HEADER: usize = 8;

impl fmt::Debug for FatHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:x} nfat_arch: {}\n", self.magic, self.nfat_arch)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
/// The Mach-o `FatArch` always has its data bigendian
pub struct FatArch {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}

pub const SIZEOF_FAT_ARCH: usize = 20;

impl fmt::Debug for FatArch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "cputype: {} cpusubtype: {} offset: {} size: {} align: {}\n",
               cputype::cpu_type_to_str(self.cputype),
               self.cpusubtype,
               self.offset,
               self.size,
               self.align)
    }
}

impl FatHeader {
    pub fn from_bytes(bytes: &[u8; SIZEOF_FAT_HEADER]) -> FatHeader {
        let mut offset = 0;
        let magic = bytes.gread_with(&mut offset, scroll::BE).unwrap();
        let nfat_arch = bytes.gread_with(&mut offset, scroll::BE).unwrap();
        FatHeader {
            magic: magic,
            nfat_arch: nfat_arch,
        }
    }

    pub fn from_fd(fd: &mut File) -> io::Result<FatHeader> {
        let mut header = [0; SIZEOF_FAT_HEADER];
        try!(fd.read(&mut header));
        Ok(FatHeader::from_bytes(&header))
    }

    /// Parse a mach-o fat header from the `buffer`
    pub fn parse<S: AsRef<[u8]>>(buffer: &S) -> error::Result<FatHeader> {
        let mut offset = 0;
        let magic = buffer.gread_with(&mut offset, scroll::BE)?;
        let nfat_arch = buffer.gread_with(&mut offset, scroll::BE)?;
        Ok(FatHeader { magic: magic, nfat_arch: nfat_arch })
    }

}

impl FatArch {
    pub fn new(bytes: &[u8; SIZEOF_FAT_ARCH]) -> FatArch {
        let mut offset = 0;
        let cputype = bytes.gread_with(&mut offset, scroll::BE).unwrap();
        let cpusubtype = bytes.gread_with(&mut offset, scroll::BE).unwrap();
        let offset_ = bytes.gread_with(&mut offset, scroll::BE).unwrap();
        let size = bytes.gread_with(&mut offset, scroll::BE).unwrap();
        let align = bytes.gread_with(&mut offset, scroll::BE).unwrap();
        FatArch {
            cputype: cputype,
            cpusubtype: cpusubtype,
            offset: offset_,
            size: size,
            align: align,
        }
    }

    pub fn is_64(&self) -> bool {
        self.cputype == cputype::CPU_TYPE_X86_64 || self.cputype == cputype::CPU_TYPE_ARM64
    }

    pub fn parse_arches<S: AsRef<[u8]>>(fd: &S, mut offset: usize, count: usize) -> error::Result<Vec<Self>> {
        let mut archs = Vec::with_capacity(count);
        let offset = &mut offset;
        for _ in 0..count {
            let mut arch = Self::default();
            arch.cputype = fd.gread_with(offset, scroll::BE)?;
            arch.cpusubtype = fd.gread_with(offset, scroll::BE)?;
            arch.offset = fd.gread_with(offset, scroll::BE)?;
            arch.size = fd.gread_with(offset, scroll::BE)?;
            arch.align = fd.gread_with(offset, scroll::BE)?;
            archs.push(arch);
        }
        Ok(archs)
    }

    // TODO: fixme this parser is now broken, hurray!
    pub fn parse<S: AsRef<[u8]>>(buffer: &S) -> error::Result<Vec<Self>> {
        let header = FatHeader::parse(buffer)?;
        let arches = FatArch::parse_arches(buffer,
                                           SIZEOF_FAT_HEADER,
                                           header.nfat_arch as usize)?;
        Ok(arches)
    }

    pub fn find_cputype(arches: &[Self], cputype: u32) -> Option<&Self> {
        arches.iter().find(|arch| arch.cputype == cputype)
    }

    pub fn find_64(arches: &[Self]) -> Option<&Self> {
        arches.iter().find(|arch| arch.is_64())
    }
}
