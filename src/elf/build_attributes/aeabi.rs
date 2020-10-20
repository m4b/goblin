//! Types for Arm public tags in the `aeabi` build attributes section.
//!
//! These tags are defined by [Addenda to, and Errata in, the ABI for the Arm® Architecture].
//!
//! [Addenda to, and Errata in, the ABI for the Arm® Architecture]: https://github.com/ARM-software/abi-aa/blob/master/addenda32/addenda32.rst#public-aeabi-attribute-tags

use super::*;

build_attributes!(
/// A set of Arm embedded ABI properties.
Aeabi {
    vendor_name: b"aeabi"
    unknown_tag: attr => {
        // Spec says:
        //
        // Tags 0-63 convey information that a consuming tool must comprehend. This includes all the
        // tags (1-32) defined by the first release (v1.0) of this addendum. A tool encountering an
        // unknown tag in this range should stop processing or take similar defensive action
        // (Q-o-I).
        //
        // Tags 64-127 convey information a consumer can ignore safely (though maybe with degraded
        // functionality).
        //
        // For N >= 128, tag N has the same properties as tag N modulo 128.
        //
        // To allow an ignored tag and its parameter value to be skipped easily, we adopt this
        // convention.
        //
        // * For N > 32, even numbered tags have a ULEB128 parameter and odd numbered ones have a
        //   null-terminated byte string (NTBS) parameter.
        // * A consumer must comprehend tags 1-32 individually.
        match attr.tag_number() % 128 {
            // Tags 0-63 must be understood, so if we don't know about them, that's an error
            n if n <= 63 => return Err(attr.unrecognized()),
            // Tags 64-127 may be ignored
            // Even tags are ULEB128
            n if n % 2 == 0 => attr.parse_uleb128()?.1,
            // Odd tags are NTBS
            n if n % 2 == 1 => attr.parse_ntbs()?.1,
            // This branch can't be reached, but the match grammar can't provide it
            _ => unreachable!(),
        }
    }

    /// The raw name is the name a user gave to a tool or selected from a menu. It can be:
    ///
    ///   * The name of a specific manufacturer's part (such as ML692000)
    ///   * The name of a generic part (such as Arm946E-S) or architecture (such as v5TE)
    ///   * Any other name acceptable to the tool chain
    ///
    /// The value `""` denotes that the raw name is identical to `cpu_name` and records that the
    /// user built for a generic implementation (such as Arm946E-S) rather than any
    /// manufacturer-specific part (such as ML692000) based on it.
    [cpu_raw_name, (=4), CpuRawName(NTBS)]

    /// A CPU name is defined by Arm or the architecture licensee responsible for designing the
    /// part. It is the official product name, with no extension and no abbreviation.
    ///
    /// An Arm-defined architecture name may be used instead of a CPU name, and denotes that the
    /// user had more generic intentions.
    [cpu_name, (=5), CpuName(NTBS)]

    /// The following tags describe the processor architecture version and architecture profile for
    /// which the user intended the producer to produce code.
    ///
    /// Starting with architecture versions v8-A, v8-R and v8-M, the profile is represented by
    /// `cpu_arch`. For earlier versions, the profile is stored separately in `cpu_arch_profile`.
    [cpu_arch, (=6), CpuArch {
        /// Pre-v4
        0 => PreV4,
        /// Arm v4, e.g. SA110
        1 => V4,
        /// Arm v4T, e.g. Arm7TDMI
        2 => V4t,
        /// Arm v5T, e.g. Arm9TDMI
        3 => V5t,
        /// Arm v5TE, e.g. Arm946E-S
        4 => V5te,
        /// Arm v5TEJ, e.g. Arm926EJ-S
        5 => V5tej,
        /// Arm v6, e.g. Arm1136J-S
        6 => V6,
        /// Arm v6KZ, e.g. Arm1176JZ-S
        7 => V6kz,
        /// Arm v6T2, e.g. Arm1156T2F-S
        8 => V6t2,
        /// Arm v6K, e.g. Arm1136J-S
        9 => V6k,
        // Arm v7, e.g. Cortex-A8, Cortex-M3
        10 => V7,
        /// Arm v6-M, e.g. Cortex-M1
        11 => V6m,
        /// Arm v6-SM, i.e. v6-M with the System extensions
        12 => V6sm,
        /// Arm v7-EM, i.e. v7-M with DSP extensions
        13 => V7em,
        /// Arm v8-A
        14 => V8a,
        /// Arm v8-R
        15 => V8r,
        /// Arm v8-M.baseline
        16 => V8mBaseline,
        /// Arm v8-M.mainline
        17 => V8mMainline,
        /// Arm v8.1-A
        18 => V81a,
        /// Arm v8.2-A
        19 => V82a,
        /// Arm v8.3-A
        20 => V83a,
        /// Arm v8.1-M.mainline
        21 => V81mMainline,
    }]

    /// `cpu_arch_profile` states that the attributed entity requires the noted architecture
    /// profile.
    ///
    /// Starting with architecture versions v8-A, v8-R and v8-M, the profile is represented by
    /// `cpu_arch`. For these architecture versions and any later versions, a value of
    /// `NotApplicable` should be used for `cpu_arch_profile`.
    [cpu_arch_profile, (=7), CpuArchProfile {
        /// Architecture profile is not applicable (e.g. pre v7, or cross-profile code) or is
        /// indicated by `cpu_arch`.
        ///
        /// This value states that there is no requirement for any specific architecture profile.
        0 => NotApplicable,
        /// The application profile (e.g. for Cortex-A8)
        0x41 => Application,
        /// The real-time profile (e.g. for Cortex-R4)
        0x52 => Realtime,
        /// The microcontroller profile (e.g. for Cortex-M3)
        0x4D => Microcontroller,
        /// Application or real-time profile (i.e. the ‘classic’ programmer’s model).
        ///
        /// This value denotes that the attributed entity requires the classic programmer's model
        /// rather than the microcontroller programmer's model.
        0x53 => Classic,
    }]

    /// Are Arm instructions permitted?
    [arm_isa_use, (=8), ArmIsaUse {
        /// The user did not permit this entity to use Arm instructions
        0 => NotPermitted,
        /// The user intended that this entity could use Arm instructions.
        ///
        /// The architecture revision (`cpu_arch` and `cpu_arch_profile`) implies the permitted
        /// subset of instructions.
        1 => Intended,
    }]

    /// Are Thumb instructions permitted?
    [thumb_isa_use, (=9), ThumbIsaUse {
        /// The user did not permit this entity to use Thumb instructions
        0 => NotPermitted,
        /// The user permitted this entity to use 16-bit Thumb instructions (including BL)
        ///
        /// This value was defined when there was a clear separation between implementations using
        /// 16-bit only Thumb instructions and those using the extended set of instructions. The
        /// introduction of `Armv8-M.baseline` has blurred this distinction to the point where it is
        /// no longer useful. Arm recommends that in future all toolchains emit a value of
        /// `Intended` when use of Thumb was intended by the user and `NotPermitted` when use of
        /// Thumb was not intended.
        1 => SixteenBitPermitted,
        /// 32-bit Thumb instructions were permitted (implies 16-bit instructions permitted)
        ///
        /// This value was defined when there was a clear separation between implementations using
        /// 16-bit only Thumb instructions and those using the extended set of instructions. The
        /// introduction of `Armv8-M.baseline` has blurred this distinction to the point where it is
        /// no longer useful. Arm recommends that in future all toolchains emit a value of
        /// `Intended` when use of Thumb was intended by the user and `NotPermitted` when use of
        /// Thumb was not intended.
        2 => ThirtyTwoBitPermitted,
        /// The user permitted this entity to use Thumb code.
        ///
        /// The architecture revision (`cpu_arch` and `cpu_arch_profile`) implies the permitted
        /// subset of instructions.
        3 => Intended,
    }]

    /// Which floating point instructions and registers are permitted?
    [fp_arch, (=10), FpArch {
        /// The user did not permit this entity to use instructions requiring FP hardware
        0 => NotPermitted,
        /// The user permitted use of instructions from v1 of the floating point (FP) ISA
        1 => V1,
        /// Use of the v2 FP ISA was permitted (implies use of the v1 FP ISA)
        2 => V2,
        /// Use of the v3 FP ISA was permitted (implies use of the v2 FP ISA)
        3 => V3,
        /// Use of the v3 FP ISA was permitted, but only citing registers D0-D15, S0-S31
        4 => V3D16,
        /// Use of the v4 FP ISA was permitted (implies use of the non-vector v3 FP ISA)
        5 => V4,
        /// Use of the v4 FP ISA was permitted, but only citing registers D0-D15, S0-S31
        6 => V4D16,
        /// Use of the Arm v8-A FP ISA was permitted
        7 => Neon,
        /// Use of the Arm v8-A FP ISA was permitted, but only citing registers D0-D15, S0-S31
        8 => NeonD16,
    }]

    /// Are WMMX instructions permitted?
    [wmmx_arch, (=11), WmmxArch {
        /// The user did not permit this entity to use WMMX
        0 => NotPermitted,
        /// The user permitted this entity to use WMMX v1
        1 => V1,
        /// The user permitted this entity to use WMMX v2
        2 => V2,
    }]

    // Are Advanced SIMD Architecture (Neon) instructions permitted?
    [advanced_simd_arch, (=12), AdvancedSimdArch {
        /// The user did not permit this entity to use the Advanced SIMD Architecture (Neon)
        0 => NotPermitted,
        /// Use of the Advanced SIMDv1 Architecture (Neon) was permitted
        1 => V1,
        /// Use of Advanced SIMDv2 Architecture (Neon) (with half-precision floating-point and fused
        /// MAC operations) was permitted
        2 => V2,
        /// Use of the Arm v8-A Advanced SIMD Architecture (Neon) was permitted
        3 => V8a,
        /// Use of the Arm v8.1-A Advanced SIMD Architecture (Neon) was permitted
        4 => V81a,
    }]

    // Are M-profile Vector Extension instructions permitted?
    [mve_arch, (=48), MveArch {
        /// The user did not permit this entity to use the M-profile Vector Extension
        0 => NotPermitted,
        /// Use of the Integer M-profile Vector Extension was permitted
        1 => Integer,
        /// Use of the Integer and Floating Point M-profile Vector Extension was permitted
        2 => IntegerAndFloatingPoint,
    }]

    /// Are half-precision floating point instructions permitted?
    [fp_hp_extension, (=36), FpHpExtension {
        /// The user intended half-precision floating point instructions may be used if they exist
        /// in the available FP and ASIMD instruction sets as indicated by `fp_arch` and
        /// `asimd_arch`.
        0 => Implied,
        /// Use of the half-precision instructions first added as an optional extension to
        /// VFPv3/Advanced SIMDv1 was permitted, in addition to those indicated by `fp_arch` and
        /// `asimd_arch`.
        1 => Vfpv3,
        /// Use of the half-precision instructions first added as an optional extension to Armv8.2-A
        /// Floating-Point and Advanced SIMD was permitted, in addition to those indicated by
        /// `fp_arch` and `asimd_arch`.
        2 => Armv82a,
    }]

    /// Are unaligned memory accesses permitted?
    [cpu_unaligned_access, (=34), CpuUnalignedAccess {
        /// The user did not intend this entity to make unaligned data accesses
        0 => NotIntended,
        /// The user intended that this entity might make v6-style unaligned data accesses
        1 => V6,
    }]

    /// Are `ENTERX` and `LEAVEX` instructions permitted?
    #[deprecated(since="ABI r2.09")]
    [t2ee_use, (=66), T2eeUse {
        /// No use of T2EE extension was permitted, or no information is available
        0 => NotPermitted,
        /// Use of the T2EE extension was permitted
        1 => Permitted,
    }]

    /// Are the TrustZone extension or virtualization extensions permitted?
    [virtualization_use, (=68), VirtualizationUse {
        /// No use of any virtualization extension was permitted, or no information available
        0 => NotPermitted,
        /// Use of the TrustZone extension (`SMC`) was permitted
        1 => TrustZone,
        /// Use of the virtualization extensions (`HVC`, `ERET`) were permitted
        2 => VirtualizationExtensions,
        /// Use of TrustZone (`SMC`) and virtualization extensions (`HVC`, `ERET`) were permitted
        3 => TrustZoneAndVirtualizationExtensions,
    }]

    /// Is the multiprocessing extension permitted?
    [mp_extension_use, (=42), MpExtensionUse {
        /// No use of Arm v7 MP extension was permitted, or no information available.
        0 => NotPermitted,
        /// Use of the Arm v7 MP extension was permitted.
        ///
        /// This enables the `PLDW` (preload write hint) instruction.
        1 => V7,
    }]

    /// Are integer division instructions permitted?
    [div_use, (=44), DivUse {
        /// The user intended divide instructions may be used if they exist, or no explicit
        /// information recorded. This code was permitted to use `SDIV` and `UDIV` if the
        /// instructions are guaranteed present in the architecture, as indicated by `cpu_arch` and
        /// `cpu_arch_profile`.
        0 => Implied,
        /// This code was explicitly not permitted to use `SDIV` or `UDIV`.
        ///
        /// `NotPermitted` records an explicit intention to not use divide instructions in this
        /// code, on targets where they would otherwise be permitted. This intention could be
        /// conveyed to the object producer by citing a "no divide" command-line option, or by
        /// other means.
        1 => NotPermitted,
        /// This code was permitted to use `SDIV` and `UDIV` in the Arm and Thumb ISAs. the
        /// instructions are present as an optional architectural extension above the base
        /// architecture implied by `cpu_arch` and `cpu_arch_profile`.
        ///
        /// Producers must emit `Permitted` if and only if the permission to use `SDIV` and `UDIV`
        /// cannot be conveyed using values `Implied` or `NotPermitted`.
        2 => Permitted,
    }]

    /// Are DSP instructions permitted?
    [dsp_extension, (=46), DspExtension {
        /// The user intended DSP instructions may be used if they exist. This entity is permitted
        /// to use DSP instructions if they are guaranteed present in the architecture as indicated
        /// by `cpu_arch`.
        0 => Implied,
        /// This code was permitted to use Thumb DSP functions as an optional architecture extension
        /// above the base architecture as indicated by `cpu_arch`.
        1 => ThumbPermitted,
    }]

    /// Summarizes the user intention behind the procedure-call standard configuration used. Its
    /// value must be consistent with the values given to the tags below, and must not be used as a
    /// macro in place of them.
    [pcs_config, (=13), PcsConfig {
        /// No standard configuration used, or no information recorded
        0 => Unspecified,
        /// Bare platform configuration
        1 => Bare,
        /// Linux application configuration
        2 => Linux,
        /// Linux DSO configuration
        3 => LinuxDso,
        /// Palm OS 2004 configuration
        4 => PalmOs2004,
        /// Reserved to future Palm OS configuration
        5 => FuturePalmOs,
        /// Symbian OS 2004 configuration
        6 => SymbianOs2004,
        /// Reserved to future Symbian OS configuration
        7 => FutureSymbianOs,
    }]

    /// R9 has a role in some variants of the PCS. `abi_pcs_r9_use` describes the user’s chosen PCS
    /// variant.
    [abi_pcs_r9_use, (=14), AbiPcsR9Use {
        /// R9 used as V6 (just another callee-saved register, implied by omitting the tag)
        0 => Default,
        /// R9 used as SB, a global Static Base register
        1 => StaticBase,
        /// R9 used as a Thread Local Storage (TLS) pointer
        ///
        /// In this mode, R9 plays the role that would otherwise be played by one of the three
        /// Software Thread ID Registers `TPIDRURW`, `TPIDRURO`, `TPIDRPRW` defined in section
        /// B3.12.46 (CP15 c13 Software Thread ID registers) of the Arm Architecture Reference
        /// Manual Arm v7-A and Arm v7-R edition.
        ///
        /// The role played by that `TPID*` register is defined by the software platform’s ABI.
        2 => ThreadLocalStorage,
        /// R9 not used at all by code associated with the attributed entity
        3 => Unused,
    }]

    /// How may the attributed entity access read-write static data?
    [abi_pcs_rw_data, (=15), AbiPcsRwData {
      /// RW static data was permitted to be addressed absolutely
      0 => Absolute,
      /// RW static data was only permitted to be addressed PC-relative
      1 => PcRelative,
      /// RW static data was only permitted to be addressed SB-relative
      2 => SbRelative,
      /// The user did not permit this entity to use RW static data
      3 => NotPermitted,
    }]

    /// How may the attributed entity access read-only static data?
    [abi_pcs_ro_data, (=16), AbiPcsRoData {
      /// RO static data was permitted to be addressed absolutely
      0 => Absolute,
      /// RO static data was only permitted to be addressed PC-relative
      1 => PcRelative,
      /// The user did not permit this entity to use RO static data
      2 => NotPermitted,
    }]

    /// Compatibility among shared objects and their clients is affected by whether imported data
    /// are addressed directly or indirectly. Linux imported data must be addressed indirectly (via
    /// the Global Object Table, or GOT). Symbian OS (2004) imported data must be addressed
    /// directly.
    [abi_pcs_got_use, (=17), AbiPcsGotUse {
      /// The user did not permit this entity to import static data
      0 => NotPermitted,
      /// The user permitted this entity to address imported data directly
      1 => Direct,
      /// The user permitted this entity to address imported data indirectly (e.g. via a GOT)
      2 => Indirect,
    }]

    /// How is `wchar_t` defined?
    [abi_pcs_wchar_t, (=18), AbiPcsWcharT {
      /// The user prohibited the use of wchar_t when building this entity
      0 => Prohibited,
      /// The user intended the size of wchar_t to be 2
      2 => TwoBytes,
      /// The user intended the size of wchar_t to be 4
      4 => FourBytes,
    }]

    /// How does this ABI handle enumerations?
    [abi_enum_size, (=26), AbiEnumSize {
        /// The user prohibited the use of enums when building this entity
        0 => Prohibited,
        /// Enum values occupy the smallest container big enough to hold all their values
        1 => Containerized,
        /// The user intended Enum containers to be 32-bit
        2 => ThirtyTwoBit,
        /// The user intended that every enumeration visible across an ABI-complying interface
        /// contains a value needing 32 bits to encode it; other enums can be containerized.
        3 => ThirtyTwoBitOverAbi,
    }]

    [abi_align_needed, (=24), AbiAlignNeeded {
      /// The user did not permit code to depend the alignment of 8-byte data or data with extended
      /// (> 8-byte) alignment
      0 => None,
      /// Code was permitted to depend on the 8-byte alignment of 8-byte data items
      1 => EightBytes,
      /// Code was permitted to depend on the 4-byte alignment of 8-byte data items
      2 => FourBytes,
      // TODO:
      // n  (in 4..12) Code was permitted to depend on the 8-byte alignment of 8-byte data items and
      // the alignment of data items having up to 2n-byte extended alignment
    }]

    [abi_align_preserved, (=25), AbiAlignPreserved {
      /// The user did not require code to preserve 8-byte alignment of 8-byte data objects
      0 => None,
      /// Code was required to preserve 8-byte alignment of 8-byte data objects
      ///
      /// This requirement is specifically enforced at function calls, which means that leaf
      /// functions (those which do not make additional function calls) may use whichever alignment
      /// is convenient.
      1 => EightBytesExceptLeaf,
      ///  Code was required to preserve 8-byte alignment of 8-byte data objects and to ensure
      /// `(SP MOD 8) = 0` at all instruction boundaries (not just at function calls)
      2 => EightBytesAlways,
      // TODO:
      // n (in 4..12) Code was required to preserve the alignments of case 2 and the alignment of
      // data items having up to 2n-byte extended alignment.
    }]

    [abi_fp_rounding, (=19), AbiFpRounding {
      /// The user intended this code to use the IEEE 754 round to nearest rounding mode
      0 => RoundToNearest,
      /// The user permitted this code to choose the IEEE 754 rounding mode at run time
      1 => ChosenAtRuntime,
    }]

    [abi_fp_denormal, (=20), AbiFpDenormal {
      /// The user built this code knowing that denormal numbers might be flushed to (+) zero
      0 => MayFlushToZero,
      /// The user permitted this code to depend on IEEE 754 denormal numbers
      1 => MustPreserveValue,
      /// The user permitted this code to depend on the sign of a flushed-to-zero number being preserved in the sign of 0
      2 => MustPreserveSign,
    }]

    [abi_fp_extensions, (=21), AbiFpExtensions {
      /// The user intended that this code should not check for inexact results
      0 => NotPermitted,
      /// The user permitted this code to check the IEEE 754 inexact exception
      1 => MayCheckInexactException,
    }]

    [abi_fp_user_exceptions, (=22), AbiFpUserExceptions {
      /// The user intended that this code should not enable or use IEEE user exceptions
      0 => NotPermitted,
      /// The user permitted this code to enables and use IEEE 754 user exceptions
      1 => Permitted,
    }]

    [abi_fp_number_model, (=23), AbiFpNumberModel {
      /// The user intended that this code should not use floating point numbers
      0 => None,
      /// The user permitted this code to use IEEE 754 format normal numbers only
      1 => Finite,
      /// The user permitted numbers, infinities, and one quiet NaN (see RTABI32)
      2 => RtAbi,
      /// The user permitted this code to use all the IEEE 754-defined FP encodings
      3 => Ieee754,
    }]

    [abi_fp_16bit_format, (=38), AbiFp16BitFormat {
        /// The user intended that this entity should not use 16-bit floating point numbers
        0 => None,
        /// Use of IEEE 754 (draft, November 2006) format 16-bit FP numbers was permitted
        1 => Ieee754,
        /// Use of VFPv3/Advanced SIMD "alternative format" 16-bit FP numbers was permitted
        2 => AlternativeFormat,
    }]

    [abi_hard_fp_use, (=27), AbiHardFpUse {
        /// The user intended that FP use should be implied by `fp_arch`
        0 => Implied,
        /// The user intended this code to execute on the single-precision variant derived from
        /// `fp_arch`
        1 => SinglePrecision,
        /// The user intended that FP use should be implied by `fp_arch`
        #[deprecated(note="This is a duplicate value; use `Implied`")]
        3 => ImpliedAgain,
    }]

    [abi_vfp_args, (=28), AbiVfpArgs {
        /// The user intended FP parameter/result passing to conform to AAPCS, base variant
        0 => Aapcs,
        /// The user intended FP parameter/result passing to conform to AAPCS, VFP variant
        1 => Vfp,
        /// The user intended FP parameter/result passing to conform to tool chain-specific conventions
        2 => Custom,
        /// Code is compatible with both the base and VFP variants; the user did not permit
        /// non-variadic functions to pass FP parameters/results
        3 => Compatible,
    }]

    [abi_wmmx_args, (=29), AbiWmmxArgs {
        /// The user intended WMMX parameter/result passing conform to the AAPCS, base variant
        0 => Base,
        /// The user intended WMMX parameter/result passing conform to Intel’s WMMX conventions
        1 => Wmmx,
        /// The user intended WMMX parameter/result passing conforms to tool chain-specific conventions
        2 => Custom,
    }]

    [frame_pointer_use, (=72), FramePointerUse {
        /// This code makes no claims to conformance with the rules for use of a frame pointer
        0 => Unspecified,
        /// This code creates a frame record for all functions that may modify the value stored in
        /// the link register (`LR`)
        1 => CreatesFrameRecords,
        /// This code does not create frame records, but preserves the value stored in the frame
        /// pointer register (`FP`)
        2 => PreservesFramePointer,
    }]

    [abi_optimization_goals, (=30), AbiOptimizationGoals {
        /// No particular optimization goals, or no information recorded
        0 => Unspecified,
        /// Optimized for speed, but small size and good debug illusion preserved
        1 => Speed,
        /// Optimized aggressively for speed, small size and debug illusion sacrificed
        2 => BestSpeed,
        /// Optimized for small size, but speed and debugging illusion preserved
        3 => Size,
        /// Optimized aggressively for small size, speed and debug illusion sacrificed
        4 => BestSize,
        /// Optimized for good debugging, but speed and small size preserved
        5 => Debugging,
        /// Optimized for best debugging illusion, speed and small size sacrificed
        6 => BestDebugging,
    }]

    [abi_fp_optimization_goals, (=31), AbiFpOptimizationGoals {
        /// No particular FP optimization goals, or no information recorded
        0 => Unspecified,
        /// Optimized for speed, but small size and good accuracy preserved
        1 => Speed,
        /// Optimized aggressively for speed, small size and accuracy sacrificed
        2 => BestSpeed,
        /// Optimized for small size, but speed and accuracy preserved
        3 => Size,
        /// Optimized aggressively for small size, speed and accuracy sacrificed
        4 => BestSize,
        /// Optimized for accuracy, but speed and small size preserved
        5 => Accuracy,
        /// Optimized for best accuracy, speed and small size sacrificed
        6 => BestAccuracy,
    }]

    // TODO: docs
    [compatibility, (=32), Compatibility(Uleb128, NTBS)]

    /// At this release of the ABI (2020Q3) there are only two defined uses of
    /// `also_compatible_with`:
    ///
    /// * To express v4T also compatible with v6-M and v6-M also compatible with v4T.
    /// * To express v8-A also compatible with v8-R and v8-R also compatible with v8-A.
    // TODO: define constants
    [also_compatible_with, (=65), AlsoCompatibleWith(Uleb128, NTBS)]

    [conformance, (=67), Conformance(NTBS)]
});

// `VirtualizationUse` is documented to be a bitfield, so provide bitwise accessors
impl VirtualizationUse {
    /// Is the `SMC` instruction intended to be used?
    pub fn smc(&self) -> bool {
        u64::from(self) & 0x01 != 0
    }

    /// Are the the `HVC` and `ERET` instructions intended to be used?
    pub fn hvc_and_eret(&self) -> bool {
        u64::from(self) & 0x02 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        // readelf says:
        // Attribute Section: aeabi
        // File Attributes
        //   Tag_CPU_name: "7-A"
        //   Tag_CPU_arch: v7
        //   Tag_CPU_arch_profile: Application
        //   Tag_ARM_ISA_use: Yes
        //   Tag_THUMB_ISA_use: Thumb-2
        //   Tag_FP_arch: VFPv3
        //   Tag_Advanced_SIMD_arch: NEONv1
        //   Tag_ABI_PCS_wchar_t: 4
        //   Tag_ABI_FP_denormal: Needed
        //   Tag_ABI_FP_exceptions: Needed
        //   Tag_ABI_FP_number_model: IEEE 754
        //   Tag_ABI_align_needed: 8-byte
        //   Tag_ABI_align_preserved: 8-byte, except leaf SP
        //   Tag_ABI_enum_size: int
        //   Tag_ABI_VFP_args: VFP registers
        //   Tag_CPU_unaligned_access: v6
        //   Tag_MPextension_use: Allowed
        //   Tag_Virtualization_use: TrustZone
        let expected = Aeabi {
            cpu_name: Some(CpuName(b"7-A")),
            cpu_arch: Some(CpuArch::V7),
            cpu_arch_profile: Some(CpuArchProfile::Application),
            arm_isa_use: Some(ArmIsaUse::Intended),
            thumb_isa_use: Some(ThumbIsaUse::ThirtyTwoBitPermitted),
            fp_arch: Some(FpArch::V3),
            advanced_simd_arch: Some(AdvancedSimdArch::V1),
            abi_pcs_wchar_t: Some(AbiPcsWcharT::FourBytes),
            abi_fp_denormal: Some(AbiFpDenormal::MustPreserveValue),
            abi_fp_extensions: Some(AbiFpExtensions::MayCheckInexactException),
            abi_fp_number_model: Some(AbiFpNumberModel::Ieee754),
            abi_align_needed: Some(AbiAlignNeeded::EightBytes),
            abi_align_preserved: Some(AbiAlignPreserved::EightBytesExceptLeaf),
            abi_enum_size: Some(AbiEnumSize::ThirtyTwoBit),
            abi_vfp_args: Some(AbiVfpArgs::Vfp),
            cpu_unaligned_access: Some(CpuUnalignedAccess::V6),
            mp_extension_use: Some(MpExtensionUse::V7),
            virtualization_use: Some(VirtualizationUse::TrustZone),
            ..Default::default()
        };

        let bytes = b"\x41\x36\x00\x00\x00\x61\x65\x61\x62\x69\x00\x01\x2c\x00\x00\x00\
        \x05\x37\x2d\x41\x00\x06\x0a\x07\x41\x08\x01\x09\x02\x0a\x03\x0c\x01\x12\x04\x14\x01\x15\
        \x01\x17\x03\x18\x01\x19\x01\x1a\x02\x1c\x01\x22\x01\x2a\x01\x44\x01";

        let section = Section::new(bytes, scroll::Endian::Little).unwrap();
        let actual = Aeabi::try_from(section).unwrap();
        assert_eq!(actual, expected);
    }
}
