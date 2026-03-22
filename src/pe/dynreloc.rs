use core::fmt;
use core::iter::FusedIterator;

use alloc::string::String;
use scroll::Pread;
use scroll::ctx;

use crate::container::{Container, Ctx};
use crate::error;
use crate::pe::relocation::{RelocationBlockIterator, RelocationWord};

/// Indicates Return Flow (RF) prologue guard relocation for dynamic relocation entries
pub const IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE: u64 = 0x00000001;
/// Indicates Return Flow (RF) epilogue guard relocation for dynamic relocation entries
pub const IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE: u64 = 0x00000002;
/// Indicates import control transfer guard relocation for dynamic relocation entries
pub const IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER: u64 = 0x00000003;
/// Indicates indirect control transfer guard relocation for dynamic relocation entries
pub const IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER: u64 = 0x00000004;
/// Indicates switch table branch guard relocation for dynamic relocation entries
pub const IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH: u64 = 0x00000005;
/// Indicates ARM64X architecture-specific dynamic relocation
pub const IMAGE_DYNAMIC_RELOCATION_ARM64X: u64 = 0x00000006;
/// Indicates function override dynamic relocation for hot patching or function replacement
pub const IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE: u64 = 0x00000007;
/// Indicates ARM64 kernel import call transfer dynamic relocation
pub const IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER: u64 = 0x00000008;

/// Represents a dynamic value relocation data.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocData<'a> {
    /// The DVRT version (must be `1` or `2`)
    pub version: u32,
    // Whether this is 64-bit architecture data
    is_64: bool,
    /// Raw data covering whole DVRT data
    bytes: &'a [u8],
}

impl<'a> DynRelocData<'a> {
    /// Parse dynamic relocation data from a byte slice and offset.
    pub fn parse(bytes: &'a [u8], is_64: bool, mut offset: usize) -> error::Result<Self> {
        let version = bytes.gread_with(&mut offset, scroll::LE)?;
        if !matches!(version, 1 | 2) {
            return Err(error::Error::Malformed(format!(
                "Unsupported DVRT version: {version}"
            )));
        }
        let size = bytes.gread_with::<u32>(&mut offset, scroll::LE)?;
        let bytes = bytes.gread_with::<&[u8]>(&mut offset, size as usize)?;

        Ok(Self {
            version,
            is_64,
            bytes,
        })
    }

    /// Returns an iterator over the dynamic relocation entries.
    pub fn entries(&self) -> DynRelocEntryIterator<'a> {
        DynRelocEntryIterator {
            bytes: self.bytes,
            is_64: self.is_64,
            offset: 0,
        }
    }
}

/// An import control transfer dynamic relocation entry.
///
/// See `IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION` in Windows SDK.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct ImportControlTransferDynReloc(u32);

impl fmt::Debug for ImportControlTransferDynReloc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportControlTransferDynReloc")
            .field("page_relative_offset", &self.page_relative_offset())
            .field("indirect_call", &self.indirect_call())
            .field("iat_index", &self.iat_index())
            .field("raw_value", &self.0)
            .finish()
    }
}

impl ImportControlTransferDynReloc {
    /// Creates a new ImportControlTransferDynReloc from individual field values
    pub fn new(page_relative_offset: u16, indirect_call: bool, iat_index: u32) -> Self {
        let page_relative_offset = (page_relative_offset as u32) & 0xFFF; // 12 bits
        let indirect_call = if indirect_call { 1u32 } else { 0u32 };
        let iat_index = iat_index & 0x7FFFF; // 19 bits

        let value = page_relative_offset | (indirect_call << 12) | (iat_index << 13);

        Self(value)
    }

    /// Creates from raw u32 value
    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Gets the PageRelativeOffset field (bits 0-11)
    pub fn page_relative_offset(&self) -> u16 {
        (self.0 & 0xFFF) as u16
    }

    /// Sets the PageRelativeOffset field (bits 0-11)
    pub fn set_page_relative_offset(&mut self, offset: u16) {
        let offset = (offset as u32) & 0xFFF;
        self.0 = (self.0 & !0xFFF) | offset;
    }

    /// Gets the IndirectCall field (bit 12)
    pub fn indirect_call(&self) -> bool {
        (self.0 >> 12) & 1 != 0
    }

    /// Sets the IndirectCall field (bit 12)
    pub fn set_indirect_call(&mut self, indirect: bool) {
        if indirect {
            self.0 |= 1 << 12;
        } else {
            self.0 &= !(1 << 12);
        }
    }

    /// Gets the IATIndex field (bits 13-31)
    pub fn iat_index(&self) -> u32 {
        (self.0 >> 13) & 0x7FFFF
    }

    /// Sets the IATIndex field (bits 13-31)
    pub fn set_iat_index(&mut self, index: u32) {
        let index = index & 0x7FFFF;
        self.0 = (self.0 & 0x1FFF) | (index << 13);
    }

    /// Returns the raw u32 value
    pub fn raw_value(&self) -> u32 {
        self.0
    }
}

/// An import control transfer ARM64 relocation entry.
///
/// See `IMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION` in Windows SDK.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct ImportControlTransferArm64Reloc(u32);

impl fmt::Debug for ImportControlTransferArm64Reloc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("ImportControlTransferArm64Reloc");

        debug_struct
            .field("page_relative_offset", &self.page_relative_offset())
            .field("byte_offset", &self.byte_offset())
            .field("instruction_type", &if self.is_br() { "BR" } else { "BLR" })
            .field("register_index", &format!("x{}", self.register_index()))
            .field(
                "import_type",
                &if self.is_static_import() {
                    "Static"
                } else {
                    "Delayload"
                },
            );

        if self.has_iat_index() {
            debug_struct.field("iat_index", &self.iat_index());
        } else {
            debug_struct.field("iat_index", &"NO_INDEX");
        }

        debug_struct.field("raw_value", &self.0).finish()
    }
}

impl ImportControlTransferArm64Reloc {
    /// Special value indicating no IAT index
    pub const NO_IAT_INDEX: u16 = 0x7FFF;

    /// Creates a new ImportControlTransferArm64Reloc from individual field values
    pub fn new(
        page_relative_offset: u16,
        indirect_call: bool,
        register_index: u8,
        import_type: bool,
        iat_index: u16,
    ) -> Self {
        let page_relative_offset = (page_relative_offset as u32) & 0x3FF; // 10 bits
        let indirect_call = if indirect_call { 1u32 } else { 0u32 };
        let register_index = (register_index as u32) & 0x1F; // 5 bits
        let import_type = if import_type { 1u32 } else { 0u32 };
        let iat_index = (iat_index as u32) & 0x7FFF; // 15 bits

        let value = page_relative_offset
            | (indirect_call << 10)
            | (register_index << 11)
            | (import_type << 16)
            | (iat_index << 17);

        Self(value)
    }

    /// Creates from raw u32 value
    pub fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Gets the PageRelativeOffset field (bits 0-9)
    /// Offset to the call instruction shifted right by 2 (4-byte aligned instruction)
    pub fn page_relative_offset(&self) -> u16 {
        (self.0 & 0x3FF) as u16
    }

    /// Sets the PageRelativeOffset field (bits 0-9)
    pub fn set_page_relative_offset(&mut self, offset: u16) {
        let offset = (offset as u32) & 0x3FF;
        self.0 = (self.0 & !0x3FF) | offset;
    }

    /// Gets the actual byte offset (PageRelativeOffset << 2)
    pub fn byte_offset(&self) -> u16 {
        self.page_relative_offset() << 2
    }

    /// Sets the PageRelativeOffset from a byte offset (byte_offset >> 2)
    pub fn set_byte_offset(&mut self, byte_offset: u16) {
        self.set_page_relative_offset(byte_offset >> 2);
    }

    /// Gets the IndirectCall field (bit 10)
    /// 0 if target instruction is a BR, 1 if BLR
    pub fn indirect_call(&self) -> bool {
        (self.0 >> 10) & 1 != 0
    }

    /// Sets the IndirectCall field (bit 10)
    pub fn set_indirect_call(&mut self, indirect: bool) {
        if indirect {
            self.0 |= 1 << 10;
        } else {
            self.0 &= !(1 << 10);
        }
    }

    /// Returns true if this is a BLR instruction, false if BR
    pub fn is_blr(&self) -> bool {
        self.indirect_call()
    }

    /// Returns true if this is a BR instruction, false if BLR
    pub fn is_br(&self) -> bool {
        !self.indirect_call()
    }

    /// Gets the RegisterIndex field (bits 11-15)
    /// Register index used for the indirect call/jump
    pub fn register_index(&self) -> u8 {
        ((self.0 >> 11) & 0x1F) as u8
    }

    /// Sets the RegisterIndex field (bits 11-15)
    pub fn set_register_index(&mut self, index: u8) {
        let index = (index as u32) & 0x1F;
        self.0 = (self.0 & !(0x1F << 11)) | (index << 11);
    }

    /// Gets the ImportType field (bit 16)
    /// 0 if this refers to a static import, 1 for delayload import
    pub fn import_type(&self) -> bool {
        (self.0 >> 16) & 1 != 0
    }

    /// Sets the ImportType field (bit 16)
    pub fn set_import_type(&mut self, is_delayload: bool) {
        if is_delayload {
            self.0 |= 1 << 16;
        } else {
            self.0 &= !(1 << 16);
        }
    }

    /// Returns true if this is a delayload import
    pub fn is_delayload_import(&self) -> bool {
        self.import_type()
    }

    /// Returns true if this is a static import
    pub fn is_static_import(&self) -> bool {
        !self.import_type()
    }

    /// Gets the IATIndex field (bits 17-31)
    /// IAT index of the corresponding import. 0x7FFF is a special value indicating no index
    pub fn iat_index(&self) -> u16 {
        ((self.0 >> 17) & 0x7FFF) as u16
    }

    /// Sets the IATIndex field (bits 17-31)
    pub fn set_iat_index(&mut self, index: u16) {
        let index = (index as u32) & 0x7FFF;
        self.0 = (self.0 & 0x1FFFF) | (index << 17);
    }

    /// Returns true if this has a valid IAT index (not the special NO_IAT_INDEX value)
    pub fn has_iat_index(&self) -> bool {
        self.iat_index() != Self::NO_IAT_INDEX
    }

    /// Sets the IAT index to the special "no index" value
    pub fn clear_iat_index(&mut self) {
        self.set_iat_index(Self::NO_IAT_INDEX);
    }

    /// Returns the raw u32 value
    pub fn raw_value(&self) -> u32 {
        self.0
    }
}

/// A DVRT ARM64X fixup record for dynamic value relocation table operations.
///
/// See `IMAGE_DVRT_ARM64X_FIXUP_RECORD` in Windows SDK.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct DVRTArm64XFixupRecord(u16);

impl fmt::Debug for DVRTArm64XFixupRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DVRTArm64XFixupRecord")
            .field("raw", &format_args!("0x{:04X}", self.0))
            .field("offset", &format_args!("0x{:03X}", self.offset()))
            .field("fixup_type", &self.fixup_type())
            .field("size", &self.size())
            .finish()
    }
}

impl DVRTArm64XFixupRecord {
    /// Creates a new DVRTArm64XFixupRecord from individual field values
    pub fn new(offset: u16, fixup_type: u8, size: u8) -> Self {
        let offset = (offset as u16) & 0xFFF; // 12 bits
        let fixup_type = (fixup_type as u16) & 0x3; // 2 bits
        let size = (size as u16) & 0x3; // 2 bits

        let value = offset | (fixup_type << 12) | (size << 14);

        Self(value)
    }

    /// Creates from raw u16 value
    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    /// Gets the Offset field (bits 0-11)
    pub fn offset(&self) -> u16 {
        self.0 & 0xFFF
    }

    /// Sets the Offset field (bits 0-11)
    pub fn set_offset(&mut self, offset: u16) {
        let offset = offset & 0xFFF;
        self.0 = (self.0 & !0xFFF) | offset;
    }

    /// Gets the Type field (bits 12-13)
    pub fn fixup_type(&self) -> u8 {
        u8::from(((self.0 >> 12) & 0x3) as u8)
    }

    /// Sets the Type field (bits 12-13)
    pub fn set_fixup_type(&mut self, fixup_type: u8) {
        let type_bits = (fixup_type as u16) & 0x3;
        self.0 = (self.0 & !(0x3 << 12)) | (type_bits << 12);
    }

    /// Gets the Size field (bits 14-15)
    /// When Type is VALUE, this represents the actual value instead of size
    pub fn size(&self) -> u8 {
        ((self.0 >> 14) & 0x3) as u8
    }

    /// Sets the Size field (bits 14-15)
    pub fn set_size(&mut self, size: u8) {
        let size = (size as u16) & 0x3;
        self.0 = (self.0 & !(0x3 << 14)) | (size << 14);
    }

    /// Sets this record as a VALUE type with the specified value
    pub fn set_value_data(&mut self, value: u8) {
        self.set_fixup_type(value);
        self.set_size(value);
    }

    /// Returns the raw u16 value
    pub fn raw_value(&self) -> u16 {
        self.0
    }

    /// Returns `true` if this is null entry
    pub fn is_null(&self) -> bool {
        self.offset() == 0 && self.fixup_type() == 0 && self.size() == 0
    }
}

/// An indirect control transfer dynamic relocation entry.
///
/// This structure represents a dynamic relocation for indirect control transfer
/// instructions such as indirect jumps or calls. The relocation is stored
/// as a 16-bit identifier that encodes the relocation type and target information.
///
/// See `IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION` in Windows SDK.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct IndirectControlTransferDynReloc(u16);

impl fmt::Debug for IndirectControlTransferDynReloc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("DynRelocIndirControlTransfer");

        debug_struct
            .field(
                "page_relative_offset",
                &format!("0x{:03X}", self.page_relative_offset()),
            )
            .field(
                "call_type",
                &if self.is_indirect_call() {
                    "Indirect"
                } else {
                    "Direct"
                },
            )
            .field(
                "operand_size",
                &if self.is_64bit_operand() {
                    "64-bit"
                } else {
                    "32-bit"
                },
            )
            .field("cfg_check", &self.has_cfg_check());

        if self.reserved() {
            debug_struct.field("reserved", &"UNEXPECTED_NON_ZERO");
        }

        debug_struct.field("raw_value", &self.0).finish()
    }
}

impl IndirectControlTransferDynReloc {
    /// Creates a new DynRelocIndirControlTransfer from individual field values
    pub fn new(
        page_relative_offset: u16,
        indirect_call: bool,
        rex_w_prefix: bool,
        cfg_check: bool,
    ) -> Self {
        let page_relative_offset = page_relative_offset & 0xFFF; // 12 bits
        let indirect_call = if indirect_call { 1u16 } else { 0u16 };
        let rex_w_prefix = if rex_w_prefix { 1u16 } else { 0u16 };
        let cfg_check = if cfg_check { 1u16 } else { 0u16 };
        // Reserved bit is always 0

        let value =
            page_relative_offset | (indirect_call << 12) | (rex_w_prefix << 13) | (cfg_check << 14);
        // bit 15 (Reserved) is left as 0

        Self(value)
    }

    /// Creates from raw u16 value
    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    /// Gets the PageRelativeOffset field (bits 0-11)
    pub fn page_relative_offset(&self) -> u16 {
        self.0 & 0xFFF
    }

    /// Sets the PageRelativeOffset field (bits 0-11)
    pub fn set_page_relative_offset(&mut self, offset: u16) {
        let offset = offset & 0xFFF;
        self.0 = (self.0 & !0xFFF) | offset;
    }

    /// Gets the IndirectCall field (bit 12)
    /// True if this is an indirect call, false if direct
    pub fn indirect_call(&self) -> bool {
        (self.0 >> 12) & 1 != 0
    }

    /// Sets the IndirectCall field (bit 12)
    pub fn set_indirect_call(&mut self, indirect: bool) {
        if indirect {
            self.0 |= 1 << 12;
        } else {
            self.0 &= !(1 << 12);
        }
    }

    /// Returns true if this is an indirect call
    pub fn is_indirect_call(&self) -> bool {
        self.indirect_call()
    }

    /// Returns true if this is a direct call
    pub fn is_direct_call(&self) -> bool {
        !self.indirect_call()
    }

    /// Gets the RexWPrefix field (bit 13)
    /// True if the instruction uses REX.W prefix (64-bit operand)
    pub fn rex_w_prefix(&self) -> bool {
        (self.0 >> 13) & 1 != 0
    }

    /// Sets the RexWPrefix field (bit 13)
    pub fn set_rex_w_prefix(&mut self, rex_w: bool) {
        if rex_w {
            self.0 |= 1 << 13;
        } else {
            self.0 &= !(1 << 13);
        }
    }

    /// Returns true if the instruction has 64-bit operand size (REX.W prefix)
    pub fn is_64bit_operand(&self) -> bool {
        self.rex_w_prefix()
    }

    /// Returns true if the instruction has 32-bit operand size (no REX.W prefix)
    pub fn is_32bit_operand(&self) -> bool {
        !self.rex_w_prefix()
    }

    /// Gets the CfgCheck field (bit 14)
    /// True if Control Flow Guard check is required
    pub fn cfg_check(&self) -> bool {
        (self.0 >> 14) & 1 != 0
    }

    /// Sets the CfgCheck field (bit 14)
    pub fn set_cfg_check(&mut self, cfg_check: bool) {
        if cfg_check {
            self.0 |= 1 << 14;
        } else {
            self.0 &= !(1 << 14);
        }
    }

    /// Returns true if Control Flow Guard check is enabled
    pub fn has_cfg_check(&self) -> bool {
        self.cfg_check()
    }

    /// Gets the Reserved field (bit 15)
    /// Should always be 0
    pub fn reserved(&self) -> bool {
        (self.0 >> 15) & 1 != 0
    }

    /// Clears the reserved bit (sets it to 0)
    pub fn clear_reserved(&mut self) {
        self.0 &= !(1 << 15);
    }

    /// Returns the raw u16 value
    pub fn raw_value(&self) -> u16 {
        self.0
    }

    /// Returns the inner u16 value (same as raw_value)
    pub fn into_inner(self) -> u16 {
        self.0
    }

    /// Creates a mutable reference to the inner u16 value
    pub fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }

    /// Creates a reference to the inner u16 value
    pub fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl Into<RelocationWord> for IndirectControlTransferDynReloc {
    fn into(self) -> RelocationWord {
        RelocationWord { value: self.0 }
    }
}

/// A switchable branch dynamic relocation entry for image switch table operations.
///
/// This structure represents a dynamic relocation that can be conditionally applied
/// based on branch switching logic in image switch tables. The relocation is stored
/// as a 16-bit identifier that encodes the relocation type and target information.
///
/// See `IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION` in Windows SDK.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct SwitchableBranchDynReloc(u16);

impl fmt::Debug for SwitchableBranchDynReloc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SwitchableBranchDynReloc")
            .field(
                "page_relative_offset",
                &format!("0x{:03X}", self.page_relative_offset()),
            )
            .field("register_number", &self.register_number())
            .field("x86_register", &self.x86_register_name())
            .field("arm64_register", &self.arm64_register_name())
            .field("raw_value", &self.0)
            .finish()
    }
}

impl SwitchableBranchDynReloc {
    /// Creates a new SwitchableBranchDynReloc from individual field values
    pub fn new(page_relative_offset: u16, register_number: u8) -> Self {
        let page_relative_offset = page_relative_offset & 0xFFF; // 12 bits
        let register_number = (register_number as u16) & 0xF; // 4 bits

        let value = page_relative_offset | (register_number << 12);

        Self(value)
    }

    /// Creates from raw u16 value
    pub fn from_raw(value: u16) -> Self {
        Self(value)
    }

    /// Gets the PageRelativeOffset field (bits 0-11)
    pub fn page_relative_offset(&self) -> u16 {
        self.0 & 0xFFF
    }

    /// Sets the PageRelativeOffset field (bits 0-11)
    pub fn set_page_relative_offset(&mut self, offset: u16) {
        let offset = offset & 0xFFF;
        self.0 = (self.0 & !0xFFF) | offset;
    }

    /// Gets the RegisterNumber field (bits 12-15)
    pub fn register_number(&self) -> u8 {
        ((self.0 >> 12) & 0xF) as u8
    }

    /// Sets the RegisterNumber field (bits 12-15)
    pub fn set_register_number(&mut self, register: u8) {
        let register = (register as u16) & 0xF;
        self.0 = (self.0 & 0xFFF) | (register << 12);
    }

    /// Gets the register name for x86/x64 architecture (assuming general-purpose registers)
    pub fn x86_register_name(&self) -> &'static str {
        match self.register_number() {
            0 => "eax/rax",
            1 => "ecx/rcx",
            2 => "edx/rdx",
            3 => "ebx/rbx",
            4 => "esp/rsp",
            5 => "ebp/rbp",
            6 => "esi/rsi",
            7 => "edi/rdi",
            8 => "r8",
            9 => "r9",
            10 => "r10",
            11 => "r11",
            12 => "r12",
            13 => "r13",
            14 => "r14",
            15 => "r15",
            _ => "unknown",
        }
    }

    /// Gets the register name for ARM64 architecture
    pub fn arm64_register_name(&self) -> String {
        format!("x{}", self.register_number())
    }

    /// Returns the raw u16 value
    pub fn raw_value(&self) -> u16 {
        self.0
    }

    /// Returns the inner u16 value (same as raw_value)
    pub fn into_inner(self) -> u16 {
        self.0
    }

    /// Creates a mutable reference to the inner u16 value
    pub fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }

    /// Creates a reference to the inner u16 value
    pub fn as_ref(&self) -> &u16 {
        &self.0
    }
}

/// Header for epilogue dynamic relocation data.
///
/// See `IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER` in Windows SDK.
#[derive(Debug, Copy, Clone)]
pub struct EpilogueDynRelocHeader {
    /// Number of epilogue sequences
    pub epilogue_count: u32,
    /// Size in bytes of each epilogue byte sequence
    pub epilogue_byte_count: u8,
    /// Size in bits of each branch descriptor element
    pub branch_descriptor_element_size: u8,
    /// Number of branch descriptor elements
    pub branch_descriptor_count: u16,
}

impl EpilogueDynRelocHeader {
    /// Size of the header in bytes
    pub const SIZE: usize = 8;

    /// Parse the header from a byte slice at the given offset.
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        let epilogue_count = bytes.gread_with::<u32>(offset, scroll::LE)?;
        let epilogue_byte_count = bytes.gread_with::<u8>(offset, scroll::LE)?;
        let branch_descriptor_element_size = bytes.gread_with::<u8>(offset, scroll::LE)?;
        let branch_descriptor_count = bytes.gread_with::<u16>(offset, scroll::LE)?;

        Ok(Self {
            epilogue_count,
            epilogue_byte_count,
            branch_descriptor_element_size,
            branch_descriptor_count,
        })
    }

    /// Returns the total size in bytes of the packed branch descriptor bitstream.
    pub fn branch_descriptors_byte_size(&self) -> usize {
        let total_bits =
            self.branch_descriptor_element_size as usize * self.branch_descriptor_count as usize;
        (total_bits + 7) / 8
    }

    /// Returns the total size in bytes of all epilogue byte sequences.
    pub fn epilogue_sequences_byte_size(&self) -> usize {
        self.epilogue_byte_count as usize * self.epilogue_count as usize
    }

    /// Returns the total size of the prefix (header + branch descriptors + epilogue sequences).
    pub fn total_prefix_size(&self) -> usize {
        Self::SIZE + self.branch_descriptors_byte_size() + self.epilogue_sequences_byte_size()
    }
}

/// Parsed epilogue dynamic relocation info containing the header, branch descriptors,
/// and epilogue byte sequences.
///
/// Access this via [`DynRelocEntry::epilogue_info`].
#[derive(Debug, Copy, Clone)]
pub struct EpilogueDynRelocInfo<'a> {
    /// The parsed epilogue header
    pub header: EpilogueDynRelocHeader,
    /// Raw bytes of the packed branch descriptor bitstream
    pub branch_descriptor_bytes: &'a [u8],
    /// Raw bytes of all epilogue byte sequences (each `header.epilogue_byte_count` bytes)
    pub epilogue_byte_sequences: &'a [u8],
}

impl<'a> EpilogueDynRelocInfo<'a> {
    /// Extracts a branch descriptor at the given index from the packed bitstream.
    ///
    /// Each descriptor is `header.branch_descriptor_element_size` bits wide.
    /// Returns `None` if the index is out of range.
    pub fn branch_descriptor(&self, index: usize) -> Option<u64> {
        if index >= self.header.branch_descriptor_count as usize {
            return None;
        }
        let bit_size = self.header.branch_descriptor_element_size as usize;
        if bit_size == 0 {
            return Some(0);
        }
        let bit_offset = index * bit_size;
        let mut value: u64 = 0;
        for i in 0..bit_size {
            let abs_bit = bit_offset + i;
            let byte_idx = abs_bit / 8;
            let bit_idx = abs_bit % 8;
            if byte_idx >= self.branch_descriptor_bytes.len() {
                return None;
            }
            if self.branch_descriptor_bytes[byte_idx] & (1 << bit_idx) != 0 {
                value |= 1 << i;
            }
        }
        Some(value)
    }

    /// Returns the epilogue byte sequence at the given index.
    ///
    /// Each sequence is `header.epilogue_byte_count` bytes long.
    /// Returns `None` if the index is out of range.
    pub fn epilogue_bytes(&self, index: usize) -> Option<&'a [u8]> {
        if index >= self.header.epilogue_count as usize {
            return None;
        }
        let byte_count = self.header.epilogue_byte_count as usize;
        let start = index * byte_count;
        let end = start + byte_count;
        if end > self.epilogue_byte_sequences.len() {
            return None;
        }
        Some(&self.epilogue_byte_sequences[start..end])
    }
}

/// Header for a single function override entry within a function override dynamic relocation.
///
/// See `IMAGE_FUNCTION_OVERRIDE_HEADER` in Windows SDK.
#[derive(Debug, Copy, Clone, Default)]
pub struct FunctionOverrideHeader {
    /// RVA of the original function
    pub original_rva: u32,
    /// Offset into the BDD (Binary Decision Diagram) data
    pub bdd_offset: u32,
    /// Size of the override RVA array in bytes
    pub rva_size: u32,
    /// Size of base relocations for this override in bytes
    pub base_reloc_size: u32,
}

impl FunctionOverrideHeader {
    /// Size of the header in bytes
    pub const SIZE: usize = 16;

    /// Parse the header from a byte slice at the given offset.
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        let original_rva = bytes.gread_with::<u32>(offset, scroll::LE)?;
        let bdd_offset = bytes.gread_with::<u32>(offset, scroll::LE)?;
        let rva_size = bytes.gread_with::<u32>(offset, scroll::LE)?;
        let base_reloc_size = bytes.gread_with::<u32>(offset, scroll::LE)?;

        Ok(Self {
            original_rva,
            bdd_offset,
            rva_size,
            base_reloc_size,
        })
    }

    /// Returns true if this is a zero-filled terminator header.
    pub fn is_terminator(&self) -> bool {
        self.original_rva == 0
            && self.bdd_offset == 0
            && self.rva_size == 0
            && self.base_reloc_size == 0
    }
}

/// A single function override entry containing override RVAs and base relocations.
#[derive(Debug, Copy, Clone)]
pub struct FunctionOverride<'a> {
    /// The parsed function override header
    pub header: FunctionOverrideHeader,
    /// Raw bytes of the override RVA array
    override_rva_bytes: &'a [u8],
    /// Raw bytes of the base relocations for this override
    base_reloc_bytes: &'a [u8],
}

impl<'a> FunctionOverride<'a> {
    /// Returns the number of override RVAs.
    pub fn rva_count(&self) -> usize {
        self.override_rva_bytes.len() / 4
    }

    /// Returns an iterator over the override RVAs.
    pub fn rvas(&self) -> FunctionOverrideRvaIterator<'a> {
        FunctionOverrideRvaIterator {
            bytes: self.override_rva_bytes,
            offset: 0,
        }
    }

    /// Returns an iterator over the base relocation blocks for this override.
    pub fn base_reloc_blocks(&self) -> RelocationBlockIterator<'a> {
        RelocationBlockIterator::from_bytes(self.base_reloc_bytes)
    }
}

/// Iterator over override RVAs within a [`FunctionOverride`].
#[derive(Debug, Copy, Clone)]
pub struct FunctionOverrideRvaIterator<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for FunctionOverrideRvaIterator<'_> {
    type Item = error::Result<u32>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        Some(
            self.bytes
                .gread_with::<u32>(&mut self.offset, scroll::LE)
                .map_err(Into::into),
        )
    }
}

impl FusedIterator for FunctionOverrideRvaIterator<'_> {}

/// BDD (Binary Decision Diagram) info header for function override relocations.
#[derive(Debug, Copy, Clone)]
pub struct BddInfo {
    /// BDD format version (must be 1)
    pub version: u32,
    /// Total size of the BDD data (including this header)
    pub size: u32,
}

impl BddInfo {
    /// Size of the BDD info header in bytes
    pub const SIZE: usize = 8;

    /// Parse BDD info from a byte slice at the given offset.
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        let version = bytes.gread_with::<u32>(offset, scroll::LE)?;
        let size = bytes.gread_with::<u32>(offset, scroll::LE)?;
        Ok(Self { version, size })
    }
}

/// A single BDD (Binary Decision Diagram) node.
#[derive(Debug, Copy, Clone)]
pub struct BddNode {
    /// Index of the left child node
    pub left: u16,
    /// Index of the right child node
    pub right: u16,
    /// Value associated with this node
    pub value: u32,
}

impl BddNode {
    /// Size of a BDD node in bytes
    pub const SIZE: usize = 8;
}

/// Iterator over BDD nodes within a function override dynamic relocation.
#[derive(Debug, Copy, Clone)]
pub struct BddNodeIterator<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for BddNodeIterator<'_> {
    type Item = error::Result<BddNode>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        let left = match self.bytes.gread_with::<u16>(&mut self.offset, scroll::LE) {
            Ok(v) => v,
            Err(e) => return Some(Err(e.into())),
        };
        let right = match self.bytes.gread_with::<u16>(&mut self.offset, scroll::LE) {
            Ok(v) => v,
            Err(e) => return Some(Err(e.into())),
        };
        let value = match self.bytes.gread_with::<u32>(&mut self.offset, scroll::LE) {
            Ok(v) => v,
            Err(e) => return Some(Err(e.into())),
        };
        Some(Ok(BddNode { left, right, value }))
    }
}

impl FusedIterator for BddNodeIterator<'_> {}

/// Iterator over function override entries.
#[derive(Debug, Copy, Clone)]
pub struct FunctionOverrideIterator<'a> {
    /// Byte slice covering only the overrides region (excludes the leading size DWORD and BDD)
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for FunctionOverrideIterator<'a> {
    type Item = error::Result<FunctionOverride<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        let header = match FunctionOverrideHeader::parse(self.bytes, &mut self.offset) {
            Ok(h) => h,
            Err(e) => {
                self.offset = self.bytes.len();
                return Some(Err(e));
            }
        };
        if header.is_terminator() {
            self.offset = self.bytes.len();
            return None;
        }
        let rva_size = header.rva_size as usize;
        let base_reloc_size = header.base_reloc_size as usize;
        let override_rva_bytes = match self.bytes.gread_with::<&[u8]>(&mut self.offset, rva_size) {
            Ok(b) => b,
            Err(e) => {
                self.offset = self.bytes.len();
                return Some(Err(e.into()));
            }
        };
        let base_reloc_bytes = match self
            .bytes
            .gread_with::<&[u8]>(&mut self.offset, base_reloc_size)
        {
            Ok(b) => b,
            Err(e) => {
                self.offset = self.bytes.len();
                return Some(Err(e.into()));
            }
        };
        Some(Ok(FunctionOverride {
            header,
            override_rva_bytes,
            base_reloc_bytes,
        }))
    }
}

impl FusedIterator for FunctionOverrideIterator<'_> {}

/// Top-level view over function override dynamic relocation data.
#[derive(Debug, Copy, Clone)]
pub struct FunctionOverrideDynRelocInfo<'a> {
    /// Size of the overrides region (from the leading DWORD)
    func_override_size: u32,
    /// Raw bytes after the leading size DWORD
    bytes: &'a [u8],
}

impl<'a> FunctionOverrideDynRelocInfo<'a> {
    /// Parse from raw entry bytes.
    fn parse(bytes: &'a [u8]) -> error::Result<Self> {
        let mut offset = 0;
        let func_override_size = bytes.gread_with::<u32>(&mut offset, scroll::LE)?;
        Ok(Self {
            func_override_size,
            bytes: &bytes[offset..],
        })
    }

    /// Returns the size of the overrides region in bytes.
    pub fn func_override_size(&self) -> u32 {
        self.func_override_size
    }

    /// Returns an iterator over the function override entries.
    pub fn overrides(&self) -> FunctionOverrideIterator<'a> {
        let end = (self.func_override_size as usize).min(self.bytes.len());
        FunctionOverrideIterator {
            bytes: &self.bytes[..end],
            offset: 0,
        }
    }

    /// Locates and parses the BDD info header.
    pub fn bdd_info(&self) -> Option<error::Result<BddInfo>> {
        // The BDD data follows immediately after the overrides region.
        let bdd_start = self.func_override_size as usize;
        if bdd_start >= self.bytes.len() {
            return None;
        }
        let mut offset = bdd_start;
        Some(BddInfo::parse(self.bytes, &mut offset))
    }

    /// Returns an iterator over the BDD nodes.
    pub fn bdd_nodes(&self) -> Option<BddNodeIterator<'a>> {
        // The BDD nodes follow immediately after the BDD info header.
        let bdd_start = self.func_override_size as usize;
        if bdd_start >= self.bytes.len() {
            return None;
        }
        let mut offset = bdd_start;
        let info = BddInfo::parse(self.bytes, &mut offset).ok()?;
        let node_bytes_len = info.size.checked_sub(BddInfo::SIZE as u32)? as usize;
        let node_bytes = self.bytes.get(offset..offset + node_bytes_len)?;
        Some(BddNodeIterator {
            bytes: node_bytes,
            offset: 0,
        })
    }
}

/// ARM64X fixup type for zero-filling memory.
///
/// Indicates that the specified memory region should be filled with zeros.
///
/// The size field determines how many bytes to zero (2, 4, or 8 bytes).
pub const IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL: u32 = 0;
/// ARM64X fixup type for immediate value patching.
///
/// When this type is used, both the Type and Size fields in the fixup record
/// contain parts of the immediate value to be written.
///
/// This allows encoding small constant values directly in the fixup record
/// without requiring additional storage.
pub const IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE: u32 = 1;
/// ARM64X fixup type for delta/offset adjustment.
///
/// Indicates that a relative offset or delta value should be applied at the
/// specified location. This is typically used for adjusting addresses or
/// offsets that need to be relocated based on the actual load address.
pub const IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA: u32 = 2;
/// ARM64X fixup size indicator for 2-byte (16-bit) operations.
///
/// Used in the Size field to indicate that the fixup operation should
/// affect 2 bytes of memory. Note that Size field value 0 is reserved,
/// so sizes start from 1.
pub const IMAGE_DVRT_ARM64X_FIXUP_SIZE_2BYTES: u32 = 1;
/// ARM64X fixup size indicator for 4-byte (32-bit) operations.
///
/// Used in the Size field to indicate that the fixup operation should
/// affect 4 bytes of memory. This is the most common size for ARM64
/// instruction patching.
pub const IMAGE_DVRT_ARM64X_FIXUP_SIZE_4BYTES: u32 = 2;
/// ARM64X fixup size indicator for 8-byte (64-bit) operations.
///
/// Used in the Size field to indicate that the fixup operation should
/// affect 8 bytes of memory. Typically used for full 64-bit address
/// or data value relocations.
pub const IMAGE_DVRT_ARM64X_FIXUP_SIZE_8BYTES: u32 = 3;

/// ARM64X-specific dynamic relocation entry.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocArm64X {
    /// Symbol identifier or target address
    pub symbol: u64,
    /// Relative Virtual Address of the containing block
    pub block_rva: u32,
    /// ARM64X fixup record containing relocation details
    pub record: DVRTArm64XFixupRecord,
}

/// Import control transfer dynamic relocation entry.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocImport {
    /// Imported symbol identifier
    pub symbol: u64,
    /// Relative Virtual Address of the containing block
    pub block_rva: u32,
    /// Import control transfer relocation record
    pub record: ImportControlTransferDynReloc,
}

/// Indirect control transfer dynamic relocation entry.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocIndirect {
    /// Symbol identifier for indirect target
    pub symbol: u64,
    /// Relative Virtual Address of the containing block
    pub block_rva: u32,
    /// Indirect control transfer relocation record
    pub record: IndirectControlTransferDynReloc,
}

/// Switchable branch dynamic relocation entry.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocBranch {
    /// Symbol identifier for branch target (64-bit)
    pub symbol: u64,
    /// Relative Virtual Address of the containing block
    pub block_rva: u32,
    /// Switchable branch relocation record
    pub record: SwitchableBranchDynReloc,
}

/// Prologue guard dynamic relocation entry.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocPrologue {
    /// Symbol identifier ([`IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE`])
    pub symbol: u64,
    /// Relative Virtual Address of the containing block
    pub block_rva: u32,
    /// Standard relocation word (type:4 bits + offset:12 bits)
    pub record: RelocationWord,
}

/// ARM64 kernel import call transfer dynamic relocation entry.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocKernelImport {
    /// Symbol identifier ([`IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER`])
    pub symbol: u64,
    /// Relative Virtual Address of the containing block
    pub block_rva: u32,
    /// ARM64 import control transfer relocation record
    pub record: ImportControlTransferArm64Reloc,
}

/// Epilogue guard dynamic relocation entry.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocEpilogue {
    /// Symbol identifier ([`IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE`])
    pub symbol: u64,
    /// Relative Virtual Address of the containing block
    pub block_rva: u32,
    /// Standard relocation word (type:4 bits + offset:12 bits)
    pub record: RelocationWord,
}

/// Dynamic relocation entry variants.
#[derive(Debug)]
pub enum DynRelocRelocation {
    /// ARM64X architecture-specific dynamic relocation
    Arm64X(DynRelocArm64X),
    /// Import control transfer dynamic relocation
    Import(DynRelocImport),
    /// Indirect control transfer dynamic relocation
    Indirect(DynRelocIndirect),
    /// Switchable branch dynamic relocation
    Branch(DynRelocBranch),
    /// Prologue guard dynamic relocation
    Prologue(DynRelocPrologue),
    /// Epilogue guard dynamic relocation
    Epilogue(DynRelocEpilogue),
    /// ARM64 kernel import call transfer dynamic relocation
    KernelImport(DynRelocKernelImport),
}

impl DynRelocRelocation {
    /// Returns the relocation offset from any variant.
    pub fn offset(&self) -> Option<u32> {
        match self {
            DynRelocRelocation::Arm64X(data) => Some(data.record.offset() as _),
            DynRelocRelocation::Import(data) => Some(data.record.page_relative_offset() as _),
            DynRelocRelocation::Indirect(data) => Some(data.record.page_relative_offset() as _),
            DynRelocRelocation::Branch(data) => Some(data.record.page_relative_offset() as _),
            DynRelocRelocation::Prologue(data) => Some(data.record.offset() as _),
            DynRelocRelocation::Epilogue(data) => Some(data.record.offset() as _),
            DynRelocRelocation::KernelImport(data) => {
                Some(data.record.page_relative_offset() as _)
            }
        }
    }
}

/// A dynamic relocation entry containing multiple relocation blocks for a symbol.
///
/// # Hierarchy
/// ```text
/// DynRelocEntry (per symbol)
///   └── DynRelocBlock (per base RVA)
///       └── DynRelocRelocation (individual relocations)
/// ```
#[derive(Debug, Copy, Clone)]
pub struct DynRelocEntry<'a> {
    /// The target symbol identifier (64-bit) for all blocks in this entry
    pub symbol: u64,
    /// Raw binary data containing the relocation blocks
    bytes: &'a [u8],
}

/// Iterator over dynamic relocation entries in a relocation table.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocEntryIterator<'a> {
    /// Raw binary data containing relocation entries
    bytes: &'a [u8],
    /// Whether to parse as 64-bit architecture data
    is_64: bool,
    /// Current parsing offset within the bytes
    offset: usize,
}

impl<'a> DynRelocEntry<'a> {
    /// Returns an iterator over the relocation blocks within this entry.
    pub fn blocks(&self) -> DynRelocBlockIterator<'a> {
        // For epilogue entries (symbol=2), the iterator starts after the epilogue prefix
        // (header + branch descriptors + epilogue byte sequences).
        //
        // For function override entries (symbol=7), returns an empty iterator.
        // Use [`Self::function_override_info`] instead.
        let offset = match self.symbol {
            IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE => {
                self.epilogue_prefix_size().unwrap_or(self.bytes.len())
            }
            IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE => {
                return DynRelocBlockIterator {
                    symbol: self.symbol,
                    bytes: &[],
                    offset: 0,
                };
            }
            _ => 0,
        };
        DynRelocBlockIterator {
            symbol: self.symbol,
            bytes: self.bytes,
            offset,
        }
    }

    /// Returns the epilogue header, branch descriptors, and epilogue byte sequences
    /// for epilogue entries (symbol=2).
    ///
    /// Returns `None` if this entry is not an epilogue entry.
    pub fn epilogue_info(&self) -> Option<error::Result<EpilogueDynRelocInfo<'a>>> {
        if self.symbol != IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE {
            return None;
        }
        let mut offset = 0;
        let header = match EpilogueDynRelocHeader::parse(self.bytes, &mut offset) {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };
        let bd_size = header.branch_descriptors_byte_size();
        let branch_descriptor_bytes = match self.bytes.get(offset..offset + bd_size) {
            Some(b) => b,
            None => {
                return Some(Err(error::Error::Malformed(
                    "Epilogue branch descriptors truncated".into(),
                )));
            }
        };
        offset += bd_size;
        let es_size = header.epilogue_sequences_byte_size();
        let epilogue_byte_sequences = match self.bytes.get(offset..offset + es_size) {
            Some(b) => b,
            None => {
                return Some(Err(error::Error::Malformed(
                    "Epilogue byte sequences truncated".into(),
                )));
            }
        };
        Some(Ok(EpilogueDynRelocInfo {
            header,
            branch_descriptor_bytes,
            epilogue_byte_sequences,
        }))
    }

    /// Returns the function override dynamic relocation info for function override
    /// entries (symbol=7).
    ///
    /// Returns `None` if this entry is not a function override entry.
    pub fn function_override_info(
        &self,
    ) -> Option<error::Result<FunctionOverrideDynRelocInfo<'a>>> {
        if self.symbol != IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE {
            return None;
        }
        Some(FunctionOverrideDynRelocInfo::parse(self.bytes))
    }

    /// Computes the DWORD-aligned prefix size for epilogue entries.
    fn epilogue_prefix_size(&self) -> Option<usize> {
        let mut offset = 0;
        let header = EpilogueDynRelocHeader::parse(self.bytes, &mut offset).ok()?;
        let prefix = header.total_prefix_size();
        // DWORD-align
        Some((prefix + 3) & !3)
    }
}

impl<'a> ctx::TryFromCtx<'a, Ctx> for DynRelocEntry<'a> {
    type Error = error::Error;

    fn try_from_ctx(bytes: &'a [u8], ctx: Ctx) -> error::Result<(Self, usize)> {
        let mut offset = 0;
        let symbol = if ctx.is_big() {
            bytes.gread_with::<u64>(&mut offset, scroll::LE)?
        } else {
            bytes.gread_with::<u32>(&mut offset, scroll::LE)? as _
        };
        let size_baserel = bytes.gread_with::<u32>(&mut offset, scroll::LE)?;
        let bytes = bytes.gread_with::<&'a [u8]>(&mut offset, size_baserel as usize)?;

        Ok((Self { symbol, bytes }, offset))
    }
}

impl<'a> Iterator for DynRelocEntryIterator<'a> {
    type Item = error::Result<DynRelocEntry<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let ctx = Ctx::new(
            if self.is_64 {
                Container::Big
            } else {
                Container::Little
            },
            scroll::LE,
        );
        Some(
            match self
                .bytes
                .gread_with::<DynRelocEntry>(&mut self.offset, ctx)
            {
                Ok(x) => Ok(x),
                Err(err) => {
                    self.bytes = &[];
                    Err(err.into())
                }
            },
        )
    }
}

impl FusedIterator for DynRelocEntryIterator<'_> {}

/// A dynamic relocation block containing multiple relocation entries.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocBlock<'a> {
    /// The target symbol identifier
    pub symbol: u64,
    /// Base Relative Virtual Address for this relocation block
    pub rva: u32,
    /// Raw binary data containing the relocation entries
    bytes: &'a [u8],
}

impl<'a> DynRelocBlock<'a> {
    /// Returns an iterator over the relocations in this block.
    pub fn relocations(&self) -> DynRelocRelocationIterator<'a> {
        DynRelocRelocationIterator {
            symbol: self.symbol,
            bytes: self.bytes,
            offset: 0,
            block_rva: self.rva,
        }
    }
}

/// Iterator over dynamic relocation blocks within a relocation entry.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocBlockIterator<'a> {
    /// The symbol identifier shared by all blocks in this iterator
    symbol: u64,
    /// Raw binary data containing the relocation blocks
    bytes: &'a [u8],
    /// Current parsing offset within the bytes
    offset: usize,
}

impl<'a> Iterator for DynRelocBlockIterator<'a> {
    type Item = error::Result<DynRelocBlock<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let mut offset = self.offset;
        let rva = match self.bytes.gread_with::<u32>(&mut offset, scroll::LE) {
            Ok(x) => x,
            Err(_) => {
                self.bytes = &[];
                return None;
            }
        };
        let size = match self.bytes.gread_with::<u32>(&mut offset, scroll::LE) {
            Ok(x) => x,
            Err(_) => {
                self.bytes = &[];
                return None;
            }
        };

        // 8 = sizeof(rva) + sizeof(size)
        if size < 8 {
            self.bytes = &[];
            return None;
        }

        Some(
            match self
                .bytes
                .gread_with::<&[u8]>(&mut self.offset, size as usize)
            {
                Ok(x) => Ok(DynRelocBlock {
                    symbol: self.symbol,
                    rva,
                    bytes: &x[8..], // Skip sizeof(rva) + sizeof(size)
                }),
                Err(err) => {
                    self.bytes = &[];
                    Err(err.into())
                }
            },
        )
    }
}

impl FusedIterator for DynRelocBlockIterator<'_> {}

/// Iterator over individual dynamic relocations within a relocation block.
#[derive(Debug, Copy, Clone)]
pub struct DynRelocRelocationIterator<'a> {
    /// The symbol identifier from the parent entry
    symbol: u64,
    /// Raw binary data containing the relocation records
    bytes: &'a [u8],
    /// Current parsing offset within the bytes
    offset: usize,
    /// Base RVA of the containing block for address calculations
    block_rva: u32,
}

impl Iterator for DynRelocRelocationIterator<'_> {
    type Item = error::Result<DynRelocRelocation>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let reloc = match self.symbol {
            IMAGE_DYNAMIC_RELOCATION_ARM64X => {
                let record = DVRTArm64XFixupRecord(
                    self.bytes
                        .gread_with::<u16>(&mut self.offset, scroll::LE)
                        .ok()?,
                );

                if record.is_null() {
                    return None; // Reached the last entry
                }

                DynRelocRelocation::Arm64X(DynRelocArm64X {
                    symbol: self.symbol,
                    block_rva: self.block_rva,
                    record,
                })
            }
            IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER => {
                let record = ImportControlTransferDynReloc(
                    self.bytes
                        .gread_with::<u32>(&mut self.offset, scroll::LE)
                        .ok()?,
                );

                DynRelocRelocation::Import(DynRelocImport {
                    symbol: self.symbol,
                    block_rva: self.block_rva,
                    record,
                })
            }
            IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER => {
                let record = IndirectControlTransferDynReloc(
                    self.bytes
                        .gread_with::<u16>(&mut self.offset, scroll::LE)
                        .ok()?,
                );
                let reloc = Into::<RelocationWord>::into(record);

                if record.page_relative_offset() == 0 || reloc.reloc_type() == 0 {
                    return None; // Reached the last entry
                }

                DynRelocRelocation::Indirect(DynRelocIndirect {
                    symbol: self.symbol,
                    block_rva: self.block_rva,
                    record,
                })
            }
            IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH => {
                let record = SwitchableBranchDynReloc(
                    self.bytes
                        .gread_with::<u16>(&mut self.offset, scroll::LE)
                        .ok()?,
                );

                if record.page_relative_offset() == 0 {
                    return None; // Reached the last entry.
                }

                DynRelocRelocation::Branch(DynRelocBranch {
                    symbol: self.symbol,
                    block_rva: self.block_rva,
                    record,
                })
            }
            IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE => {
                let record = RelocationWord {
                    value: self
                        .bytes
                        .gread_with::<u16>(&mut self.offset, scroll::LE)
                        .ok()?,
                };

                if record.reloc_type() == 0 {
                    return None; // IMAGE_REL_BASED_ABSOLUTE padding
                }

                DynRelocRelocation::Prologue(DynRelocPrologue {
                    symbol: self.symbol,
                    block_rva: self.block_rva,
                    record,
                })
            }
            IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE => {
                let record = RelocationWord {
                    value: self
                        .bytes
                        .gread_with::<u16>(&mut self.offset, scroll::LE)
                        .ok()?,
                };

                if record.reloc_type() == 0 {
                    return None; // IMAGE_REL_BASED_ABSOLUTE padding
                }

                DynRelocRelocation::Epilogue(DynRelocEpilogue {
                    symbol: self.symbol,
                    block_rva: self.block_rva,
                    record,
                })
            }
            IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER => {
                let record = ImportControlTransferArm64Reloc(
                    self.bytes
                        .gread_with::<u32>(&mut self.offset, scroll::LE)
                        .ok()?,
                );

                DynRelocRelocation::KernelImport(DynRelocKernelImport {
                    symbol: self.symbol,
                    block_rva: self.block_rva,
                    record,
                })
            }
            IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE => {
                // Function override uses a different access path via
                // DynRelocEntry::function_override_info(), not base relocation blocks.
                self.bytes = &[];
                return None;
            }
            // IMAGE_DYNAMIC_RELOCATION_KI_USER_SHARED_DATA64 etc
            x if x > u8::MAX as _ => {
                self.bytes = &[];
                return None;
            }
            _ => {
                self.bytes = &[];
                return None;
            }
        };

        Some(Ok(reloc))
    }
}

impl FusedIterator for DynRelocRelocationIterator<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    /// DVRT data that contain 263 Import, 21 Indirect and 2 Branch dynamic relocations.
    const DVRT_DATA_IMPORT_INDIRECT_BRANCH: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x20, 0x05, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x7C, 0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x23, 0x30,
        0x03, 0x00, 0xC7, 0xD0, 0x02, 0x00, 0x38, 0x11, 0x03, 0x00, 0x9A, 0x51, 0x03, 0x00, 0x07,
        0x72, 0x03, 0x00, 0x2A, 0xB2, 0x02, 0x00, 0xBA, 0xB2, 0x02, 0x00, 0x4D, 0xB3, 0x02, 0x00,
        0xB9, 0xB3, 0x02, 0x00, 0xFF, 0x93, 0x03, 0x00, 0x2D, 0xB4, 0x02, 0x00, 0xAC, 0xF4, 0x02,
        0x00, 0xCE, 0xB4, 0x02, 0x00, 0x6E, 0xB5, 0x02, 0x00, 0x13, 0xB6, 0x02, 0x00, 0xAA, 0xDF,
        0x08, 0x00, 0x00, 0x20, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x2C, 0x10, 0x07, 0x00, 0xA9,
        0xB3, 0x02, 0x00, 0x64, 0xB4, 0x02, 0x00, 0xC4, 0xB4, 0x02, 0x00, 0x39, 0xB5, 0x02, 0x00,
        0x02, 0xB7, 0x02, 0x00, 0x55, 0x97, 0x0A, 0x00, 0x6A, 0x97, 0x0A, 0x00, 0xE2, 0xB7, 0x02,
        0x00, 0x23, 0xB8, 0x02, 0x00, 0xA7, 0x78, 0x0A, 0x00, 0xC6, 0x08, 0x00, 0x00, 0xD2, 0x28,
        0x00, 0x00, 0xDE, 0x48, 0x00, 0x00, 0xEA, 0x68, 0x00, 0x00, 0xF6, 0x88, 0x00, 0x00, 0x02,
        0xA9, 0x00, 0x00, 0x0E, 0xC9, 0x00, 0x00, 0x1A, 0xE9, 0x00, 0x00, 0x26, 0x09, 0x01, 0x00,
        0x32, 0x29, 0x01, 0x00, 0x3E, 0x49, 0x01, 0x00, 0x4A, 0x69, 0x01, 0x00, 0x56, 0x89, 0x01,
        0x00, 0x62, 0xA9, 0x01, 0x00, 0x6E, 0xC9, 0x01, 0x00, 0x7A, 0xE9, 0x01, 0x00, 0x86, 0x69,
        0x02, 0x00, 0x92, 0x29, 0x02, 0x00, 0x9E, 0x49, 0x02, 0x00, 0xA7, 0xAA, 0x06, 0x00, 0x34,
        0x0B, 0x08, 0x00, 0x00, 0x90, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0D, 0xB0, 0x02, 0x00,
        0x79, 0xB0, 0x02, 0x00, 0xBF, 0xD0, 0x03, 0x00, 0xF3, 0xB0, 0x02, 0x00, 0x5A, 0xB1, 0x03,
        0x00, 0x74, 0xB1, 0x02, 0x00, 0xD9, 0xB1, 0x02, 0x00, 0x49, 0xB2, 0x02, 0x00, 0x8A, 0xB2,
        0x02, 0x00, 0x4B, 0x93, 0x04, 0x00, 0x5B, 0x33, 0x04, 0x00, 0xF3, 0x33, 0x06, 0x00, 0xA1,
        0x15, 0x05, 0x00, 0x8E, 0x76, 0x05, 0x00, 0xE2, 0x96, 0x05, 0x00, 0xCB, 0xF7, 0x03, 0x00,
        0xAB, 0x99, 0x06, 0x00, 0x40, 0x1A, 0x04, 0x00, 0x5B, 0xDA, 0x05, 0x00, 0xD7, 0xBA, 0x02,
        0x00, 0x18, 0xBB, 0x02, 0x00, 0x73, 0xFB, 0x04, 0x00, 0x86, 0x9B, 0x06, 0x00, 0xDA, 0x1B,
        0x04, 0x00, 0xF5, 0xDB, 0x05, 0x00, 0xB9, 0xBD, 0x02, 0x00, 0x8E, 0xBE, 0x02, 0x00, 0xF4,
        0xBE, 0x02, 0x00, 0x59, 0xBF, 0x02, 0x00, 0x9A, 0xBF, 0x02, 0x00, 0x00, 0xA0, 0x00, 0x00,
        0x58, 0x00, 0x00, 0x00, 0xC8, 0xB0, 0x02, 0x00, 0x09, 0xB1, 0x02, 0x00, 0x72, 0x51, 0x05,
        0x00, 0x88, 0xB1, 0x05, 0x00, 0x07, 0xF2, 0x05, 0x00, 0xCE, 0x13, 0x06, 0x00, 0x3F, 0xD4,
        0x05, 0x00, 0x69, 0xB4, 0x02, 0x00, 0xAA, 0xB4, 0x02, 0x00, 0xC2, 0x15, 0x06, 0x00, 0x19,
        0xD6, 0x05, 0x00, 0x5D, 0xB6, 0x02, 0x00, 0x9E, 0xB6, 0x02, 0x00, 0xF4, 0x56, 0x05, 0x00,
        0x0B, 0x77, 0x04, 0x00, 0x60, 0x59, 0x04, 0x00, 0x79, 0x1B, 0x06, 0x00, 0x45, 0x5D, 0x04,
        0x00, 0xE9, 0x1D, 0x06, 0x00, 0xAF, 0xBE, 0x02, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x60, 0x00,
        0x00, 0x00, 0x72, 0x50, 0x05, 0x00, 0x63, 0x11, 0x06, 0x00, 0x1C, 0x13, 0x06, 0x00, 0x85,
        0x14, 0x06, 0x00, 0x4E, 0xB5, 0x02, 0x00, 0x96, 0xB5, 0x04, 0x00, 0x30, 0xD7, 0x04, 0x00,
        0x73, 0x57, 0x06, 0x00, 0x86, 0xD7, 0x04, 0x00, 0xA4, 0xB7, 0x02, 0x00, 0xE5, 0xB7, 0x02,
        0x00, 0x08, 0xB9, 0x02, 0x00, 0xB9, 0xBA, 0x02, 0x00, 0xFA, 0xBA, 0x02, 0x00, 0x59, 0xBB,
        0x02, 0x00, 0x9A, 0xBB, 0x02, 0x00, 0x29, 0xBC, 0x02, 0x00, 0x6A, 0xBC, 0x02, 0x00, 0xB6,
        0x7C, 0x06, 0x00, 0x26, 0x3F, 0x05, 0x00, 0x44, 0xBF, 0x02, 0x00, 0x85, 0xBF, 0x02, 0x00,
        0x00, 0xC0, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x18, 0xB0, 0x02, 0x00, 0x59, 0xB0, 0x02,
        0x00, 0xA3, 0xF0, 0x06, 0x00, 0xB4, 0x10, 0x07, 0x00, 0x08, 0xB1, 0x02, 0x00, 0x0D, 0x52,
        0x07, 0x00, 0x54, 0xF2, 0x06, 0x00, 0xBD, 0x32, 0x07, 0x00, 0x48, 0xB4, 0x02, 0x00, 0xA8,
        0xB4, 0x02, 0x00, 0xE9, 0xB4, 0x02, 0x00, 0xCD, 0xB5, 0x02, 0x00, 0x0E, 0xB6, 0x02, 0x00,
        0xF4, 0xB6, 0x02, 0x00, 0x35, 0xB7, 0x02, 0x00, 0xCE, 0xB7, 0x02, 0x00, 0x0F, 0xB8, 0x02,
        0x00, 0x24, 0xBA, 0x02, 0x00, 0x65, 0xBA, 0x02, 0x00, 0xD9, 0xBA, 0x02, 0x00, 0xA7, 0xBB,
        0x02, 0x00, 0xEF, 0xFB, 0x06, 0x00, 0x89, 0xBD, 0x02, 0x00, 0xCA, 0xBD, 0x02, 0x00, 0xC1,
        0x1E, 0x06, 0x00, 0x4B, 0xFF, 0x06, 0x00, 0x84, 0xBF, 0x02, 0x00, 0xC5, 0xBF, 0x02, 0x00,
        0x00, 0xD0, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0xCB, 0xB0, 0x02, 0x00, 0x51, 0xB1, 0x02,
        0x00, 0x92, 0xB1, 0x02, 0x00, 0x56, 0xB2, 0x02, 0x00, 0xF9, 0xBC, 0x02, 0x00, 0x3A, 0xBD,
        0x02, 0x00, 0xD3, 0xBD, 0x07, 0x00, 0xFE, 0xDD, 0x05, 0x00, 0x2B, 0x9E, 0x05, 0x00, 0xF2,
        0x7E, 0x07, 0x00, 0xD5, 0xDF, 0x07, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00,
        0xDD, 0x70, 0x05, 0x00, 0xC0, 0x91, 0x07, 0x00, 0xF5, 0xF2, 0x07, 0x00, 0x1A, 0xB4, 0x07,
        0x00, 0x3A, 0xD4, 0x05, 0x00, 0x5C, 0x94, 0x05, 0x00, 0xAD, 0xB4, 0x02, 0x00, 0xEE, 0xB4,
        0x02, 0x00, 0x62, 0x15, 0x06, 0x00, 0x8B, 0xB5, 0x08, 0x00, 0xBA, 0x55, 0x08, 0x00, 0xBE,
        0xB6, 0x02, 0x00, 0xFF, 0xB6, 0x02, 0x00, 0x25, 0x78, 0x08, 0x00, 0x08, 0x99, 0x08, 0x00,
        0xE6, 0x9A, 0x08, 0x00, 0x98, 0x9C, 0x05, 0x00, 0xFD, 0xBC, 0x02, 0x00, 0x3E, 0xBD, 0x02,
        0x00, 0x00, 0xF0, 0x00, 0x00, 0x4C, 0x00, 0x00, 0x00, 0xC9, 0xB4, 0x02, 0x00, 0x0A, 0xB5,
        0x02, 0x00, 0x89, 0xB6, 0x02, 0x00, 0xCA, 0xB6, 0x02, 0x00, 0x52, 0xB7, 0x02, 0x00, 0x59,
        0xB8, 0x02, 0x00, 0x9A, 0xB8, 0x02, 0x00, 0x21, 0xF9, 0x08, 0x00, 0xE3, 0x19, 0x09, 0x00,
        0xC4, 0xBA, 0x02, 0x00, 0x05, 0xBB, 0x02, 0x00, 0x56, 0x3B, 0x09, 0x00, 0x74, 0xBB, 0x02,
        0x00, 0xB5, 0xBB, 0x02, 0x00, 0x19, 0xBE, 0x02, 0x00, 0x14, 0x5F, 0x09, 0x00, 0x57, 0xBF,
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x6A, 0x50, 0x09, 0x00, 0x9B,
        0xB0, 0x02, 0x00, 0xE8, 0xF0, 0x06, 0x00, 0xF9, 0x10, 0x07, 0x00, 0x18, 0xF1, 0x06, 0x00,
        0x29, 0x11, 0x07, 0x00, 0x48, 0xF1, 0x06, 0x00, 0x59, 0x11, 0x07, 0x00, 0xB8, 0xF1, 0x06,
        0x00, 0xC9, 0x11, 0x07, 0x00, 0xF2, 0xF1, 0x06, 0x00, 0x03, 0x12, 0x07, 0x00, 0x76, 0xB2,
        0x02, 0x00, 0xCC, 0xB7, 0x02, 0x00, 0x0D, 0xB8, 0x02, 0x00, 0x4A, 0x79, 0x09, 0x00, 0x24,
        0xBA, 0x02, 0x00, 0x65, 0xBA, 0x02, 0x00, 0xB6, 0x9A, 0x09, 0x00, 0xDE, 0xBA, 0x02, 0x00,
        0x1F, 0xBB, 0x02, 0x00, 0x7E, 0xBB, 0x02, 0x00, 0xBF, 0xBB, 0x02, 0x00, 0x24, 0xBC, 0x02,
        0x00, 0x84, 0xBC, 0x02, 0x00, 0xE4, 0xBC, 0x02, 0x00, 0x25, 0xBD, 0x02, 0x00, 0x4B, 0xDE,
        0x09, 0x00, 0x64, 0xBF, 0x02, 0x00, 0xA5, 0xBF, 0x02, 0x00, 0x00, 0x10, 0x01, 0x00, 0x78,
        0x00, 0x00, 0x00, 0x2B, 0xD0, 0x09, 0x00, 0x84, 0xB0, 0x02, 0x00, 0xC5, 0xB0, 0x02, 0x00,
        0x5D, 0xD1, 0x05, 0x00, 0xA3, 0xB1, 0x02, 0x00, 0xE4, 0xB1, 0x02, 0x00, 0x61, 0xB2, 0x02,
        0x00, 0xA2, 0xB2, 0x02, 0x00, 0xBE, 0xB3, 0x05, 0x00, 0xE3, 0x13, 0x06, 0x00, 0x78, 0x16,
        0x06, 0x00, 0xCE, 0xF6, 0x09, 0x00, 0xE1, 0xB6, 0x05, 0x00, 0xFD, 0x16, 0x0A, 0x00, 0xC6,
        0xD7, 0x05, 0x00, 0xD7, 0x37, 0x0A, 0x00, 0x49, 0xB8, 0x02, 0x00, 0xDE, 0xD8, 0x05, 0x00,
        0x18, 0xB9, 0x02, 0x00, 0x28, 0xDB, 0x05, 0x00, 0x59, 0xBB, 0x02, 0x00, 0x9A, 0xBB, 0x02,
        0x00, 0xA0, 0xDC, 0x05, 0x00, 0xFE, 0xBC, 0x02, 0x00, 0x45, 0xBD, 0x02, 0x00, 0x9A, 0x5E,
        0x0A, 0x00, 0xE6, 0x5E, 0x05, 0x00, 0xFC, 0x1F, 0x06, 0x00, 0x00, 0x20, 0x01, 0x00, 0x30,
        0x00, 0x00, 0x00, 0x97, 0x12, 0x06, 0x00, 0xB7, 0x12, 0x06, 0x00, 0xE0, 0x13, 0x06, 0x00,
        0x00, 0x14, 0x06, 0x00, 0xC2, 0xB4, 0x02, 0x00, 0x03, 0xB5, 0x02, 0x00, 0xDC, 0x15, 0x06,
        0x00, 0xFC, 0x15, 0x06, 0x00, 0x92, 0x17, 0x06, 0x00, 0xB2, 0x17, 0x06, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x18,
        0x00, 0x00, 0x00, 0x7C, 0x50, 0x81, 0x51, 0x12, 0x59, 0x7A, 0x59, 0x06, 0x5A, 0xB2, 0x5A,
        0x8B, 0x5D, 0x11, 0x5F, 0x00, 0x20, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x67, 0x50, 0x42,
        0x56, 0xC6, 0x56, 0x80, 0x0C, 0xA0, 0x4C, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x0C, 0x00,
        0x00, 0x00, 0xB6, 0x5C, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xB3,
        0x5C, 0x6D, 0x5D, 0xC1, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x2C, 0x50, 0x9E, 0x51, 0x9F, 0x56, 0x0A, 0x57, 0x90, 0x5D, 0x00, 0x00, 0x00, 0x10, 0x01,
        0x00, 0x0C, 0x00, 0x00, 0x00, 0x19, 0x50, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x2D,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xF8, 0x02, 0x00, 0x00,
    ];

    #[test]
    fn parse_dvrt_import_indirect_branch() {
        let dvrt = DynRelocData::parse(DVRT_DATA_IMPORT_INDIRECT_BRANCH, true, 0).unwrap();
        let entries = dvrt.entries().collect::<error::Result<Vec<_>>>().unwrap();
        // Import, Indirect and Branch = 3
        assert_eq!(entries.len(), 3);

        let blocks = entries
            .iter()
            .flat_map(|e| e.blocks())
            .collect::<error::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(blocks.len(), 20);

        let relocs = blocks
            .iter()
            .flat_map(|b| b.relocations())
            .collect::<error::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(relocs.len(), 286);

        let import_relocs = entries[0]
            .blocks()
            .collect::<error::Result<Vec<_>>>()
            .unwrap()
            .iter()
            .flat_map(|b| b.relocations())
            .collect::<error::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(import_relocs.len(), 263);

        let indirect_relocs = entries[1]
            .blocks()
            .collect::<error::Result<Vec<_>>>()
            .unwrap()
            .iter()
            .flat_map(|b| b.relocations())
            .collect::<error::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(indirect_relocs.len(), 21);

        let branch_relocs = entries[2]
            .blocks()
            .collect::<error::Result<Vec<_>>>()
            .unwrap()
            .iter()
            .flat_map(|b| b.relocations())
            .collect::<error::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(branch_relocs.len(), 2);
    }

    #[test]
    #[should_panic = "Scroll(TooBig { size: 1312, len: 1308 })"]
    fn cannot_parse_less_dvrt_data() {
        let data = &DVRT_DATA_IMPORT_INDIRECT_BRANCH[..DVRT_DATA_IMPORT_INDIRECT_BRANCH.len() - 4];
        let _ = DynRelocData::parse(data, true, 0).unwrap();
    }
}
