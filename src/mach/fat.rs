//! A Mach-o fat binary is a multi-architecture binary container

use core::fmt;

use std::fs::File;
use std::io::{self, Read};

use scroll::{self, Gread, Pread};
use mach::constants::cputype;
use error;

pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_CIGAM: u32 = 0xbebafeca;

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(feature = "std", derive(Pread, Pwrite, SizeWith))]
/// The Mach-o `FatHeader` always has its data bigendian
pub struct FatHeader {
    /// The magic number, `cafebabe`
    pub magic: u32,
    /// How many fat architecture headers there are
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
#[cfg_attr(feature = "std", derive(Pread, Pwrite, SizeWith))]
/// The Mach-o `FatArch` always has its data bigendian
pub struct FatArch {
    /// What kind of CPU this binary is
    pub cputype: u32,
    pub cpusubtype: u32,
    /// Where in the fat binary it starts
    pub offset: u32,
    /// How big the binary is
    pub size: u32,
    pub align: u32,
}

pub const SIZEOF_FAT_ARCH: usize = 20;

impl fmt::Debug for FatArch {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("FatArch")
            .field("cputype", &cputype::cpu_type_to_str(self.cputype))
            .field("cmdsize", &self.cpusubtype)
            .field("offset",  &format_args!("{:#x}", &self.offset))
            .field("size",    &self.size)
            .field("align",   &self.align)
            .finish()
    }
}

impl FatHeader {
    /// Reinterpret a `FatHeader` from `bytes`
    pub fn from_bytes(bytes: &[u8; SIZEOF_FAT_HEADER]) -> FatHeader {
        let mut offset = 0;
        let magic = bytes.gread_with(&mut offset, scroll::BE).unwrap();
        let nfat_arch = bytes.gread_with(&mut offset, scroll::BE).unwrap();
        FatHeader {
            magic: magic,
            nfat_arch: nfat_arch,
        }
    }

    /// Reads a `FatHeader` from a `File` on disk
    pub fn from_fd(fd: &mut File) -> io::Result<FatHeader> {
        let mut header = [0; SIZEOF_FAT_HEADER];
        try!(fd.read(&mut header));
        Ok(FatHeader::from_bytes(&header))
    }

    /// Parse a mach-o fat header from the `buffer`
    pub fn parse(bytes: &[u8]) -> error::Result<FatHeader> {
        let mut offset = 0;
        let magic = bytes.gread_with(&mut offset, scroll::BE)?;
        let nfat_arch = bytes.gread_with(&mut offset, scroll::BE)?;
        Ok(FatHeader { magic: magic, nfat_arch: nfat_arch })
    }

}

impl FatArch {
    /// Get the slice of bytes this header describes from `bytes`
    pub fn slice<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let start = self.offset as usize;
        let end = (self.offset + self.size) as usize;
        &bytes[start..end]
    }

    /// Whether this fat header describes a 64-bit binary
    pub fn is_64(&self) -> bool {
        self.cputype == cputype::CPU_TYPE_X86_64 || self.cputype == cputype::CPU_TYPE_ARM64
    }

    pub fn parse_arches<B: AsRef<[u8]>>(bytes: B, mut offset: usize, count: usize) -> error::Result<Vec<Self>> {
        let mut archs = Vec::with_capacity(count);
        let offset = &mut offset;
        for _ in 0..count {
            archs.push(bytes.gread_with::<FatArch>(offset, scroll::BE)?);
        }
        Ok(archs)
    }
    pub fn parse(bytes: &[u8]) -> error::Result<Vec<Self>> {
        let header = FatHeader::parse(bytes)?;
        let arches = FatArch::parse_arches(bytes,
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

#[cfg(feature = "std")]
/// A Mach-o multi architecture (Fat) binary container
pub struct MultiArch<'a> {
    data: &'a [u8],
    pub narches: usize,
}

#[cfg(feature = "std")]
impl<'a> MultiArch<'a> {
    /// Lazily construct `Self`
    pub fn new(bytes: &'a [u8]) -> error::Result<Self> {
        let header = FatHeader::parse(bytes)?;
        Ok(MultiArch {
            data: bytes,
            narches: header.nfat_arch as usize
        })
    }
    /// Return all the Architectures in this binary
    pub fn arches(&self) -> error::Result<Vec<FatArch>> {
        let mut arches = Vec::with_capacity(self.narches);
        let offset = &mut 0;
        for _ in 0..self.narches {
            arches.push(self.data.gread_with::<FatArch>(offset, scroll::BE)?);
        }
        Ok(arches)
    }
    // pub fn get(&self, index: usize) -> error::Result<super::MachO<'a>> {
    //     if index >= self.narches {
    //         return Err(error::Error::Malformed(format!("Requested the {}-th binary, but there are only {} architectures in this container", index, self.narches).into()))
    //     }
    //     let mut offset = index * SIZEOF_FAT_ARCH;
    //     let arch = self.data.pread_with::<FatArch>(offset, scroll::BE)?;
    //     let bytes = arch.slice(self.data);
    //     Ok(super::MachO::parse(bytes, 0)?)
    // }
}

#[cfg(feature = "std")]
impl<'a> fmt::Debug for MultiArch<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("MultiArch")
            .field("arches:", &self.arches().unwrap())
            .field("data",    &self.data.len())
            .finish()
    }
}
