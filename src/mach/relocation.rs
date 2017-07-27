// Format of a relocation entry of a Mach-O file.  Modified from the 4.3BSD
// format.  The modifications from the original format were changing the value
// of the r_symbolnum field for "local" (r_extern == 0) relocation entries.
// This modification is required to support symbols in an arbitrary number of
// sections not just the three sections (text, data and bss) in a 4.3BSD file.
// Also the last 4 bits have had the r_type tag added to them.

// The r_address is not really the address as it's name indicates but an offset.
// In 4.3BSD a.out objects this offset is from the start of the "segment" for
// which relocation entry is for (text or data).  For Mach-O object files it is
// also an offset but from the start of the "section" for which the relocation
// entry is for.  See comments in <mach-o/loader.h> about the r_address feild
// in images for used with the dynamic linker.

// In 4.3BSD a.out objects if r_extern is zero then r_symbolnum is an ordinal
// for the segment the symbol being relocated is in.  These ordinals are the
// symbol types N_TEXT, N_DATA, N_BSS or N_ABS.  In Mach-O object files these
// ordinals refer to the sections in the object file in the order their section
// structures appear in the headers of the object file they are in.  The first
// section has the ordinal 1, the second 2, and so on.  This means that the
// same ordinal in two different object files could refer to two different
// sections.  And further could have still different ordinals when combined
// by the link-editor.  The value R_ABS is used for relocation entries for
// absolute symbols which need no further relocation.
#[derive(Copy, Clone, Debug, Pread, Pwrite, IOwrite, IOread)]
pub struct RelocationInfo {
    /// offset in the section to what is being relocated
    pub r_address: i32,
    pub r_info: u32,
}

impl RelocationInfo {
    /// symbol index if `r_extern` == 1 or section ordinal if `r_extern` == 0. In bits :24
    #[inline]
    pub fn r_symbolnum(&self) -> u32 {
        self.r_info & 0xffff_ff00u32
    }
    /// was relocated pc relative already
    #[inline]
    pub fn r_pcrel(&self) -> u8 {
        (self.r_info & 0x80) as u8
    }
    /// 0=byte, 1=word, 2=long, 3=quad
    #[inline]
    pub fn r_length(&self) -> u8 {
        (self.r_info & 0x60) as u8
    }
    /// Whether this relocation is for a symbol or a section
    #[inline]
    pub fn is_extern(&self) -> bool {
        self.r_extern() == 1
    }
    /// does not include value of sym referenced
    #[inline]
    pub fn r_extern(&self) -> u8 {
        (self.r_info & 0x10) as u8
    }
    /// if not 0, machine specific relocation type, in bits :2
    #[inline]
    pub fn r_type(&self) -> u8 {
        (self.r_info & 0xf) as u8
    }
}

/// Absolute relocation type for Mach-O files
pub const R_ABS: u8 = 0;
