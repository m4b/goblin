use std::mem;
use std::fmt;
use std::fs::File;
use std::io::{self, Seek, Read};
use std::io::SeekFrom::Start;

// Constants for the flags field of the mach_header
/// the object file has no undefined references
pub const MH_NOUNDEFS: u32 = 0x1;
/// the object file is the output of an incremental link against a base file and can't be
/// link edited again
pub const MH_INCRLINK: u32 = 0x2;
/// the object file is input for the dynamic linker and can't be staticly link edited again
pub const MH_DYLDLINK: u32 = 0x4;
/// the object file's undefined references are bound by the dynamic linker when loaded.
pub const MH_BINDATLOAD: u32 = 0x8;
/// the file has its dynamic undefined references prebound.
pub const MH_PREBOUND: u32 = 0x10;
/// the file has its read-only and read-write segments split
pub const MH_SPLIT_SEGS: u32 = 0x20;
/// the shared library init routine is to be run lazily via catching memory faults to its writeable
/// segments (obsolete)
pub const MH_LAZY_INIT: u32 = 0x40;
/// the image is using two-level name space bindings
pub const MH_TWOLEVEL: u32 = 0x80;
/// the executable is forcing all images to use flat name space bindings
pub const MH_FORCE_FLAT: u32 = 0x100;
/// this umbrella guarantees no multiple defintions of symbols in its sub-images so the
/// two-level namespace hints can always be used.
pub const MH_NOMULTIDEFS: u32 = 0x200;
/// do not have dyld notify the prebinding agent about this executable
pub const MH_NOFIXPREBINDING: u32 = 0x400;
/// the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set.
pub const MH_PREBINDABLE: u32 = 0x800;
/// indicates that this binary binds to all two-level namespace modules of its dependent libraries.
/// Only used when MH_PREBINDABLE and MH_TWOLEVEL are both set.
pub const MH_ALLMODSBOUND: u32 = 0x1000;
/// safe to divide up the sections into sub-sections via symbols for dead code stripping
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
/// the binary has been canonicalized via the unprebind operation
pub const MH_CANONICAL: u32 = 0x4000;
/// the final linked image contains external weak symbols
pub const MH_WEAK_DEFINES: u32 = 0x8000;
/// the final linked image uses weak symbols
pub const MH_BINDS_TO_WEAK: u32 = 0x10000;
/// When this bit is set, all stacks in the task will be given stack execution privilege.
/// Only used in MH_EXECUTE filetypes.
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;
/// When this bit is set, the binary declares it is safe for use in processes with uid zero
pub const MH_ROOT_SAFE: u32 = 0x40000;
/// When this bit is set, the binary declares it is safe for use in processes when issetugid() is true
pub const MH_SETUID_SAFE: u32 = 0x80000;
/// When this bit is set on a dylib,  the static linker does not need to examine dependent dylibs to
/// see if any are re-exported
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x100000;
/// When this bit is set, the OS will load the main executable at a random address.
/// Only used in MH_EXECUTE filetypes.
pub const MH_PIE: u32 = 0x200000;
/// Only for use on dylibs.  When linking against a dylib that has this bit set, the static linker
/// will automatically not create a LC_LOAD_DYLIB load command to the dylib if no symbols are being
/// referenced from the dylib.
pub const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x400000;
/// Contains a section of type S_THREAD_LOCAL_VARIABLES
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x800000;
/// When this bit is set, the OS will run the main executable with a non-executable heap even on
/// platforms (e.g. i386) that don't require it. Only used in MH_EXECUTE filetypes.
pub const MH_NO_HEAP_EXECUTION: u32 = 0x1000000;

// TODO: verify this number is correct, it was previously 0x02000000 which could indicate a typo/data entry error
pub const MH_APP_EXTENSION_SAFE: u32 = 0x2000000; // The code was linked for use in an application extension.

#[inline(always)]
pub fn flag_to_str(flag: u32) -> &'static str {
    match flag {
        MH_NOUNDEFS => "MH_NOUNDEFS",
        MH_INCRLINK => "MH_INCRLINK",
        MH_DYLDLINK => "MH_DYLDLINK",
        MH_BINDATLOAD => "MH_BINDATLOAD",
        MH_PREBOUND => "MH_PREBOUND",
        MH_SPLIT_SEGS => "MH_SPLIT_SEGS",
        MH_LAZY_INIT => "MH_LAZY_INIT",
        MH_TWOLEVEL => "MH_TWOLEVEL",
        MH_FORCE_FLAT => "MH_FORCE_FLAT",
        MH_NOMULTIDEFS => "MH_NOMULTIDEFS",
        MH_NOFIXPREBINDING => "MH_NOFIXPREBINDING",
        MH_PREBINDABLE => "MH_PREBINDABLE ",
        MH_ALLMODSBOUND => "MH_ALLMODSBOUND",
        MH_SUBSECTIONS_VIA_SYMBOLS => "MH_SUBSECTIONS_VIA_SYMBOLS",
        MH_CANONICAL => "MH_CANONICAL",
        MH_WEAK_DEFINES => "MH_WEAK_DEFINES",
        MH_BINDS_TO_WEAK => "MH_BINDS_TO_WEAK",
        MH_ALLOW_STACK_EXECUTION => "MH_ALLOW_STACK_EXECUTION",
        MH_ROOT_SAFE => "MH_ROOT_SAFE",
        MH_SETUID_SAFE => "MH_SETUID_SAFE",
        MH_NO_REEXPORTED_DYLIBS => "MH_NO_REEXPORTED_DYLIBS",
        MH_PIE => "MH_PIE",
        MH_DEAD_STRIPPABLE_DYLIB => "MH_DEAD_STRIPPABLE_DYLIB",
        MH_HAS_TLV_DESCRIPTORS => "MH_HAS_TLV_DESCRIPTORS",
        MH_NO_HEAP_EXECUTION => "MH_NO_HEAP_EXECUTION",
        MH_APP_EXTENSION_SAFE => "MH_APP_EXTENSION_SAFE",
        _ => "UNKNOWN FLAG",
    }
}

/// Mach Header magic constant
pub const MH_MAGIC: u32 = 0xfeedface;
pub const MH_CIGAM: u32 = 0xcefaedfe;
/// Mach Header magic constant for 64-bit
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const MH_CIGAM_64: u32 = 0xcffaedfe;

// Constants for the filetype field of the mach_header
/// relocatable object file
pub const MH_OBJECT: u32 = 0x1;
/// demand paged executable file
pub const MH_EXECUTE: u32 = 0x2;
/// fixed VM shared library file
pub const MH_FVMLIB: u32 = 0x3;
/// core file
pub const MH_CORE: u32 = 0x4;
/// preloaded executable file
pub const MH_PRELOAD: u32 = 0x5;
/// dynamically bound shared library
pub const MH_DYLIB: u32 = 0x6;
/// dynamic link editor
pub const MH_DYLINKER: u32 = 0x7;
/// dynamically bound bundle file
pub const MH_BUNDLE: u32 = 0x8;
/// shared library stub for static linking only, no section contents
pub const MH_DYLIB_STUB: u32 = 0x9;
/// companion file with only debug sections
pub const MH_DSYM: u32 = 0xa;
/// x86_64 kexts
pub const MH_KEXT_BUNDLE: u32 = 0xb;

pub fn filetype_to_str(filetype: u32) -> &'static str {
    match filetype {
        MH_OBJECT => "OBJECT",
        MH_EXECUTE => "EXECUTE",
        MH_FVMLIB => "FVMLIB",
        MH_CORE => "CORE",
        MH_PRELOAD => "PRELOAD",
        MH_DYLIB => "DYLIB",
        MH_DYLINKER => "DYLINKER",
        MH_BUNDLE => "BUNDLE",
        MH_DYLIB_STUB => "DYLIB_STUB",
        MH_DSYM => "DSYM",
        MH_KEXT_BUNDLE => "KEXT_BUNDLE",
        _ => "UNKNOWN FILETYPE",
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Header {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u8,
    pub padding1: u8,
    pub padding2: u8,
    pub caps: u8,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

pub const SIZEOF_MACH_HEADER: usize = 32;

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "0x{:x} {} {} 0x{:x} {} {} {} 0x{:x} 0x{:x}",
               self.magic,
               self.cputype,
               self.cpusubtype,
               self.caps,
               filetype_to_str(self.filetype),
               self.ncmds,
               self.sizeofcmds,
               self.flags,
               self.reserved)
    }
}

impl Header {
    /// Returns the corresponding Mach-o header from the given byte array
    pub fn from_bytes(bytes: &[u8; SIZEOF_MACH_HEADER]) -> &Header {
        let header: &Header = unsafe { mem::transmute(bytes) };
        header
    }

    // #[cfg(feature = "no_endian_fd")]
    pub fn from_fd(fd: &mut File, offset: u64) -> io::Result<Header> {
        let mut header = [0; SIZEOF_MACH_HEADER];
        try!(fd.seek(Start(offset)));
        try!(fd.read(&mut header));
        Ok(*Header::from_bytes(&header))
    }
}
