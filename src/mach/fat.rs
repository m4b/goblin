use std::fmt;
use std::path::Path;
use std::fs::File;
use std::io::{self, Read, Seek};
use std::io::SeekFrom::Start;
use super::constants::cputype;

use byteorder::{BigEndian, ReadBytesExt};

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
        use std::io::Cursor;
        let mut cursor = Cursor::new(bytes);
        let magic = cursor.read_u32::<BigEndian>().unwrap();
        let nfat_arch = cursor.read_u32::<BigEndian>().unwrap();
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
}

impl FatArch {
    pub fn new(bytes: &[u8; SIZEOF_FAT_ARCH]) -> FatArch {
        use std::io::Cursor;
        let mut cursor = Cursor::new(bytes);
        let cputype = cursor.read_u32::<BigEndian>().unwrap();
        let cpusubtype = cursor.read_u32::<BigEndian>().unwrap();
        let offset = cursor.read_u32::<BigEndian>().unwrap();
        let size = cursor.read_u32::<BigEndian>().unwrap();
        let align = cursor.read_u32::<BigEndian>().unwrap();
        FatArch {
            cputype: cputype,
            cpusubtype: cpusubtype,
            offset: offset,
            size: size,
            align: align,
        }
    }

    pub fn is_64(&self) -> bool {
        self.cputype == cputype::CPU_TYPE_X86_64 || self.cputype == cputype::CPU_TYPE_ARM64
    }

    pub fn from_fd(fd: &mut File, offset: u64, count: usize, _: bool) -> io::Result<Vec<Self>> {
        let mut archs = Vec::with_capacity(count);
        try!(fd.seek(Start(offset)));
        for _ in 0..count {
            let mut arch = Self::default();
            arch.cputype = try!(fd.read_u32::<BigEndian>());
            arch.cpusubtype = try!(fd.read_u32::<BigEndian>());
            arch.offset = try!(fd.read_u32::<BigEndian>());
            arch.size = try!(fd.read_u32::<BigEndian>());
            arch.align = try!(fd.read_u32::<BigEndian>());
            archs.push(arch);
        }
        Ok(archs)
    }

    pub fn from_path(path: &Path) -> io::Result<Vec<Self>> {
        let mut fd = try!(File::open(&path));
        let header = try!(FatHeader::from_fd(&mut fd));
        let arches = try!(FatArch::from_fd(&mut fd,
                                           SIZEOF_FAT_HEADER as u64,
                                           header.nfat_arch as usize,
                                           false));
        Ok(arches)
    }

    pub fn find_cputype(arches: &[Self], cputype: u32) -> Option<&Self> {
        arches.iter().find(|arch| arch.cputype == cputype)
    }

    pub fn find_64(arches: &[Self]) -> Option<&Self> {
        arches.iter().find(|arch| arch.is_64())
    }
}
