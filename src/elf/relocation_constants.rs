/* because of this definition, all relocations should be max 32 bits
  hence we can define the type to be 32 for ease of use, and have rela::r_type return a u32
#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
*/

// AArch64 relocs
/// No relocation
pub const R_AARCH64_NONE: u32 = 0;

// ILP32 AArch64 relocs
/// Direct 32 bit
pub const R_AARCH64_P32_ABS32: u32 = 1;
/// Copy symbol at runtime
pub const R_AARCH64_P32_COPY: u32 = 180;
/// Create GOT entry
pub const R_AARCH64_P32_GLOB_DAT: u32 = 181;
/// Create PLT entry
pub const R_AARCH64_P32_JUMP_SLOT: u32 = 182;
/// Adjust by program base
pub const R_AARCH64_P32_RELATIVE: u32 = 183;
/// Module number, 32 bit
pub const R_AARCH64_P32_TLS_DTPMOD: u32 = 184;
/// Module-relative offset, 32 bit
pub const R_AARCH64_P32_TLS_DTPREL: u32 = 185;
/// TP-relative offset, 32 bit
pub const R_AARCH64_P32_TLS_TPREL: u32 = 186;
/// TLS Descriptor
pub const R_AARCH64_P32_TLSDESC: u32 = 187;
/// STT_GNU_IFUNC relocation
pub const R_AARCH64_P32_IRELATIVE: u32 = 188;

// LP64 AArch64 relocs
/// Direct 64 bit
pub const R_AARCH64_ABS64: u32 = 257;
/// Direct 32 bit
pub const R_AARCH64_ABS32: u32 = 258;
/// Direct 16-bit
pub const R_AARCH64_ABS16: u32 = 259;
/// PC-relative 64-bit
pub const R_AARCH64_PREL64: u32 = 260;
/// PC-relative 32-bit
pub const R_AARCH64_PREL32: u32 = 261;
/// PC-relative 16-bit
pub const R_AARCH64_PREL16: u32 = 262;
/// Dir. MOVZ imm. from bits 15:0
pub const R_AARCH64_MOVW_UABS_G0: u32 = 263;
/// Likewise for MOVK; no check
pub const R_AARCH64_MOVW_UABS_G0_NC: u32 = 264;
/// Dir. MOVZ imm. from bits 31:16
pub const R_AARCH64_MOVW_UABS_G1: u32 = 265;
/// Likewise for MOVK; no check
pub const R_AARCH64_MOVW_UABS_G1_NC: u32 = 266;
/// Dir. MOVZ imm. from bits 47:32
pub const R_AARCH64_MOVW_UABS_G2: u32 = 267;
/// Likewise for MOVK; no check
pub const R_AARCH64_MOVW_UABS_G2_NC: u32 = 268;
/// Dir. MOV{K,Z} imm. from 63:48
pub const R_AARCH64_MOVW_UABS_G3: u32 = 269;
/// Dir. MOV{N,Z} imm. from 15:0
pub const R_AARCH64_MOVW_SABS_G0: u32 = 270;
/// Dir. MOV{N,Z} imm. from 31:16
pub const R_AARCH64_MOVW_SABS_G1: u32 = 271;
/// Dir. MOV{N,Z} imm. from 47:32
pub const R_AARCH64_MOVW_SABS_G2: u32 = 272;
/// PC-rel. LD imm. from bits 20:2
pub const R_AARCH64_LD_PREL_LO19: u32 = 273;
/// PC-rel. ADR imm. from bits 20:0
pub const R_AARCH64_ADR_PREL_LO21: u32 = 274;
/// Page-rel. ADRP imm. from 32:12
pub const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
/// Likewise; no overflow check
pub const R_AARCH64_ADR_PREL_PG_HI21_NC: u32 = 276;
/// Dir. ADD imm. from bits 11:0
pub const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
/// Likewise for LD/ST; no check.
pub const R_AARCH64_LDST8_ABS_LO12_NC: u32 = 278;
/// PC-rel. TBZ/TBNZ imm. from 15:2
pub const R_AARCH64_TSTBR14: u32 = 279;
/// PC-rel. cond. br. imm. from 20:2.
pub const R_AARCH64_CONDBR19: u32 = 280;
/// PC-rel. B imm. from bits 27:2
pub const R_AARCH64_JUMP26: u32 = 282;
/// Likewise for CALL
pub const R_AARCH64_CALL26: u32 = 283;
/// Dir. ADD imm. from bits 11:1
pub const R_AARCH64_LDST16_ABS_LO12_NC: u32 = 284;
/// Likewise for bits 11:2
pub const R_AARCH64_LDST32_ABS_LO12_NC: u32 = 285;
/// Likewise for bits 11:3
pub const R_AARCH64_LDST64_ABS_LO12_NC: u32 = 286;
/// PC-rel. MOV{N,Z} imm. from 15:0
pub const R_AARCH64_MOVW_PREL_G0: u32 = 287;
/// Likewise for MOVK; no check
pub const R_AARCH64_MOVW_PREL_G0_NC: u32 = 288;
/// PC-rel. MOV{N,Z} imm. from 31:16.
pub const R_AARCH64_MOVW_PREL_G1: u32 = 289;
/// Likewise for MOVK; no check
pub const R_AARCH64_MOVW_PREL_G1_NC: u32 = 290;
/// PC-rel. MOV{N,Z} imm. from 47:32.
pub const R_AARCH64_MOVW_PREL_G2: u32 = 291;
/// Likewise for MOVK; no check
pub const R_AARCH64_MOVW_PREL_G2_NC: u32 = 292;
/// PC-rel. MOV{N,Z} imm. from 63:48.
pub const R_AARCH64_MOVW_PREL_G3: u32 = 293;
/// Dir. ADD imm. from bits 11:4
pub const R_AARCH64_LDST128_ABS_LO12_NC: u32 = 299;
/// GOT-rel. off. MOV{N,Z} imm. 15:0.
pub const R_AARCH64_MOVW_GOTOFF_G0: u32 = 300;
/// Likewise for MOVK; no check
pub const R_AARCH64_MOVW_GOTOFF_G0_NC: u32 = 301;
/// GOT-rel. o. MOV{N,Z} imm. 31:16
pub const R_AARCH64_MOVW_GOTOFF_G1: u32 = 302;
/// Likewise for MOVK; no check
pub const R_AARCH64_MOVW_GOTOFF_G1_NC: u32 = 303;
/// GOT-rel. o. MOV{N,Z} imm. 47:32
pub const R_AARCH64_MOVW_GOTOFF_G2: u32 = 304;
/// Likewise for MOVK; no check
pub const R_AARCH64_MOVW_GOTOFF_G2_NC: u32 = 305;
/// GOT-rel. o. MOV{N,Z} imm. 63:48
pub const R_AARCH64_MOVW_GOTOFF_G3: u32 = 306;
/// GOT-relative 64-bit
pub const R_AARCH64_GOTREL64: u32 = 307;
/// GOT-relative 32-bit
pub const R_AARCH64_GOTREL32: u32 = 308;
/// PC-rel. GOT off. load imm. 20:2
pub const R_AARCH64_GOT_LD_PREL19: u32 = 309;
/// GOT-rel. off. LD/ST imm. 14:3
pub const R_AARCH64_LD64_GOTOFF_LO15: u32 = 310;
/// P-page-rel. GOT off. ADRP 32:12
pub const R_AARCH64_ADR_GOT_PAGE: u32 = 311;
/// Dir. GOT off. LD/ST imm. 11:3
pub const R_AARCH64_LD64_GOT_LO12_NC: u32 = 312;
/// GOT-page-rel. GOT off. LD/ST 14:3
pub const R_AARCH64_LD64_GOTPAGE_LO15: u32 = 313;
/// PC-relative ADR imm. 20:0
pub const R_AARCH64_TLSGD_ADR_PREL21: u32 = 512;
/// page-rel. ADRP imm. 32:12
pub const R_AARCH64_TLSGD_ADR_PAGE21: u32 = 513;
/// direct ADD imm. from 11:0
pub const R_AARCH64_TLSGD_ADD_LO12_NC: u32 = 514;
/// GOT-rel. MOV{N,Z} 31:16
pub const R_AARCH64_TLSGD_MOVW_G1: u32 = 515;
/// GOT-rel. MOVK imm. 15:0
pub const R_AARCH64_TLSGD_MOVW_G0_NC: u32 = 516;
/// Like 512; local dynamic model
pub const R_AARCH64_TLSLD_ADR_PREL21: u32 = 517;
/// Like 513; local dynamic model
pub const R_AARCH64_TLSLD_ADR_PAGE21: u32 = 518;
/// Like 514; local dynamic model
pub const R_AARCH64_TLSLD_ADD_LO12_NC: u32 = 519;
/// Like 515; local dynamic model
pub const R_AARCH64_TLSLD_MOVW_G1: u32 = 520;
/// Like 516; local dynamic model
pub const R_AARCH64_TLSLD_MOVW_G0_NC: u32 = 521;
/// TLS PC-rel. load imm. 20:2
pub const R_AARCH64_TLSLD_LD_PREL19: u32 = 522;
/// TLS DTP-rel. MOV{N,Z} 47:32
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G2: u32 = 523;
/// TLS DTP-rel. MOV{N,Z} 31:16
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G1: u32 = 524;
/// Likewise; MOVK; no check
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC: u32 = 525;
/// TLS DTP-rel. MOV{N,Z} 15:0
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G0: u32 = 526;
/// Likewise; MOVK; no check
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC: u32 = 527;
/// DTP-rel. ADD imm. from 23:12.
pub const R_AARCH64_TLSLD_ADD_DTPREL_HI12: u32 = 528;
/// DTP-rel. ADD imm. from 11:0
pub const R_AARCH64_TLSLD_ADD_DTPREL_LO12: u32 = 529;
/// Likewise; no ovfl. check
pub const R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC: u32 = 530;
/// DTP-rel. LD/ST imm. 11:0
pub const R_AARCH64_TLSLD_LDST8_DTPREL_LO12: u32 = 531;
/// Likewise; no check
pub const R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC: u32 = 532;
/// DTP-rel. LD/ST imm. 11:1
pub const R_AARCH64_TLSLD_LDST16_DTPREL_LO12: u32 = 533;
/// Likewise; no check
pub const R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC: u32 = 534;
/// DTP-rel. LD/ST imm. 11:2
pub const R_AARCH64_TLSLD_LDST32_DTPREL_LO12: u32 = 535;
/// Likewise; no check
pub const R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC: u32 = 536;
/// DTP-rel. LD/ST imm. 11:3
pub const R_AARCH64_TLSLD_LDST64_DTPREL_LO12: u32 = 537;
/// Likewise; no check
pub const R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC: u32 = 538;
/// GOT-rel. MOV{N,Z} 31:16
pub const R_AARCH64_TLSIE_MOVW_GOTTPREL_G1: u32 = 539;
/// GOT-rel. MOVK 15:0
pub const R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC: u32 = 540;
/// Page-rel. ADRP 32:12
pub const R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21: u32 = 541;
/// Direct LD off. 11:3
pub const R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC: u32 = 542;
/// PC-rel. load imm. 20:2
pub const R_AARCH64_TLSIE_LD_GOTTPREL_PREL19: u32 = 543;
/// TLS TP-rel. MOV{N,Z} 47:32
pub const R_AARCH64_TLSLE_MOVW_TPREL_G2: u32 = 544;
/// TLS TP-rel. MOV{N,Z} 31:16
pub const R_AARCH64_TLSLE_MOVW_TPREL_G1: u32 = 545;
/// Likewise; MOVK; no check
pub const R_AARCH64_TLSLE_MOVW_TPREL_G1_NC: u32 = 546;
/// TLS TP-rel. MOV{N,Z} 15:0
pub const R_AARCH64_TLSLE_MOVW_TPREL_G0: u32 = 547;
/// Likewise; MOVK; no check
pub const R_AARCH64_TLSLE_MOVW_TPREL_G0_NC: u32 = 548;
/// TP-rel. ADD imm. 23:12
pub const R_AARCH64_TLSLE_ADD_TPREL_HI12: u32 = 549;
/// TP-rel. ADD imm. 11:0
pub const R_AARCH64_TLSLE_ADD_TPREL_LO12: u32 = 550;
/// Likewise; no ovfl. check
pub const R_AARCH64_TLSLE_ADD_TPREL_LO12_NC: u32 = 551;
/// TP-rel. LD/ST off. 11:0
pub const R_AARCH64_TLSLE_LDST8_TPREL_LO12: u32 = 552;
/// Likewise; no ovfl. check.
pub const R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC: u32 = 553;
/// TP-rel. LD/ST off. 11:1
pub const R_AARCH64_TLSLE_LDST16_TPREL_LO12: u32 = 554;
/// Likewise; no check
pub const R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC: u32 = 555;
/// TP-rel. LD/ST off. 11:2
pub const R_AARCH64_TLSLE_LDST32_TPREL_LO12: u32 = 556;
/// Likewise; no check
pub const R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC: u32 = 557;
/// TP-rel. LD/ST off. 11:3
pub const R_AARCH64_TLSLE_LDST64_TPREL_LO12: u32 = 558;
/// Likewise; no check
pub const R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC: u32 = 559;
/// PC-rel. load immediate 20:2
pub const R_AARCH64_TLSDESC_LD_PREL19: u32 = 560;
/// PC-rel. ADR immediate 20:0
pub const R_AARCH64_TLSDESC_ADR_PREL21: u32 = 561;
/// Page-rel. ADRP imm. 32:12
pub const R_AARCH64_TLSDESC_ADR_PAGE21: u32 = 562;
/// Direct LD off. from 11:3
pub const R_AARCH64_TLSDESC_LD64_LO12: u32 = 563;
/// Direct ADD imm. from 11:0
pub const R_AARCH64_TLSDESC_ADD_LO12: u32 = 564;
/// GOT-rel. MOV{N,Z} imm. 31:16
pub const R_AARCH64_TLSDESC_OFF_G1: u32 = 565;
/// GOT-rel. MOVK imm. 15:0; no ck
pub const R_AARCH64_TLSDESC_OFF_G0_NC: u32 = 566;
/// Relax LDR
pub const R_AARCH64_TLSDESC_LDR: u32 = 567;
/// Relax ADD
pub const R_AARCH64_TLSDESC_ADD: u32 = 568;
/// Relax BLR
pub const R_AARCH64_TLSDESC_CALL: u32 = 569;
/// TP-rel. LD/ST off. 11:4
pub const R_AARCH64_TLSLE_LDST128_TPREL_LO12: u32 = 570;
/// Likewise; no check
pub const R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC: u32 = 571;
/// DTP-rel. LD/ST imm. 11:4.
pub const R_AARCH64_TLSLD_LDST128_DTPREL_LO12: u32 = 572;
/// Likewise; no check
pub const R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC: u32 = 573;
/// Copy symbol at runtime
pub const R_AARCH64_COPY: u32 = 1024;
/// Create GOT entry
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
/// Create PLT entry
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
/// Adjust by program base
pub const R_AARCH64_RELATIVE: u32 = 1027;
/// Module number, 64 bit
pub const R_AARCH64_TLS_DTPMOD: u32 = 1028;
/// Module-relative offset, 64 bit
pub const R_AARCH64_TLS_DTPREL: u32 = 1029;
/// TP-relative offset, 64 bit
pub const R_AARCH64_TLS_TPREL: u32 = 1030;
/// TLS Descriptor
pub const R_AARCH64_TLSDESC: u32 = 1031;
/// STT_GNU_IFUNC relocation
pub const R_AARCH64_IRELATIVE: u32 = 1032;

// ARM relocs
/// No reloc
pub const R_ARM_NONE: u32 = 0;
/// Deprecated PC relative 26 bit branch
pub const R_ARM_PC24: u32 = 1;
/// Direct 32 bit
pub const R_ARM_ABS32: u32 = 2;
/// PC relative 32 bit
pub const R_ARM_REL32: u32 = 3;
pub const R_ARM_PC13: u32 = 4;
/// Direct 16 bit
pub const R_ARM_ABS16: u32 = 5;
/// Direct 12 bit
pub const R_ARM_ABS12: u32 = 6;
/// Direct & 0x7C (LDR, STR)
pub const R_ARM_THM_ABS5: u32 = 7;
/// Direct 8 bit
pub const R_ARM_ABS8: u32 = 8;
pub const R_ARM_SBREL32: u32 = 9;
/// PC relative 24 bit (Thumb32 BL)
pub const R_ARM_THM_PC22: u32 = 10;
/// PC relative & 0x3FC(Thumb16 LDR, ADD, ADR).
pub const R_ARM_THM_PC8: u32 = 11;
pub const R_ARM_AMP_VCALL9: u32 = 12;
/// Obsolete static relocation
pub const R_ARM_SWI24: u32 = 13;
/// Dynamic relocation
pub const R_ARM_TLS_DESC: u32 = 13;
/// Reserved
pub const R_ARM_THM_SWI8: u32 = 14;
/// Reserved
pub const R_ARM_XPC25: u32 = 15;
/// Reserved
pub const R_ARM_THM_XPC22: u32 = 16;
/// ID of module containing symbol
pub const R_ARM_TLS_DTPMOD32: u32 = 17;
/// Offset in TLS block
pub const R_ARM_TLS_DTPOFF32: u32 = 18;
/// Offset in static TLS block
pub const R_ARM_TLS_TPOFF32: u32 = 19;
/// Copy symbol at runtime
pub const R_ARM_COPY: u32 = 20;
/// Create GOT entry
pub const R_ARM_GLOB_DAT: u32 = 21;
/// Create PLT entry
pub const R_ARM_JUMP_SLOT: u32 = 22;
/// Adjust by program base
pub const R_ARM_RELATIVE: u32 = 23;
/// 32 bit offset to GOT
pub const R_ARM_GOTOFF: u32 = 24;
/// 32 bit PC relative offset to GOT
pub const R_ARM_GOTPC: u32 = 25;
/// 32 bit GOT entry
pub const R_ARM_GOT32: u32 = 26;
/// Deprecated, 32 bit PLT address
pub const R_ARM_PLT32: u32 = 27;
/// PC relative 24 bit (BL, BLX)
pub const R_ARM_CALL: u32 = 28;
/// PC relative 24 bit (B, BL<cond>)
pub const R_ARM_JUMP24: u32 = 29;
/// PC relative 24 bit (Thumb32 B.W)
pub const R_ARM_THM_JUMP24: u32 = 30;
/// Adjust by program base
pub const R_ARM_BASE_ABS: u32 = 31;
/// Obsolete
pub const R_ARM_ALU_PCREL_7_0: u32 = 32;
/// Obsolete
pub const R_ARM_ALU_PCREL_15_8: u32 = 33;
/// Obsolete
pub const R_ARM_ALU_PCREL_23_15: u32 = 34;
/// Deprecated, prog. base relative
pub const R_ARM_LDR_SBREL_11_0: u32 = 35;
/// Deprecated, prog. base relative
pub const R_ARM_ALU_SBREL_19_12: u32 = 36;
/// Deprecated, prog. base relative
pub const R_ARM_ALU_SBREL_27_20: u32 = 37;
pub const R_ARM_TARGET1: u32 = 38;
/// Program base relative
pub const R_ARM_SBREL31: u32 = 39;
pub const R_ARM_V4BXd: u32 = 40;
pub const R_ARM_TARGET2: u32 = 41;
/// 32 bit PC relative
pub const R_ARM_PREL31: u32 = 42;
/// Direct 16-bit (MOVW)
pub const R_ARM_MOVW_ABS_NC: u32 = 43;
/// Direct high 16-bit (MOVT)
pub const R_ARM_MOVT_ABS: u32 = 44;
/// PC relative 16-bit (MOVW)
pub const R_ARM_MOVW_PREL_NC: u32 = 45;
/// PC relative (MOVT)
pub const R_ARM_MOVT_PREL: u32 = 46;
/// Direct 16 bit (Thumb32 MOVW)
pub const R_ARM_THM_MOVW_ABS_NC: u32 = 47;
/// Direct high 16 bit (Thumb32 MOVT)
pub const R_ARM_THM_MOVT_ABS: u32 = 48;
/// PC relative 16 bit (Thumb32 MOVW)
pub const R_ARM_THM_MOVW_PREL_NC: u32 = 49;
/// PC relative high 16 bit (Thumb32 MOVT)
pub const R_ARM_THM_MOVT_PREL: u32 = 50;
/// PC relative 20 bit (Thumb32 B<cond>.W)
pub const R_ARM_THM_JUMP19: u32 = 51;
/// PC relative X & 0x7E (Thumb16 CBZ, CBNZ)
pub const R_ARM_THM_JUMP6: u32 = 52;
/// PC relative 12 bit (Thumb32 ADR.W)
pub const R_ARM_THM_ALU_PREL_11_0: u32 = 53;
/// PC relative 12 bit (Thumb32 LDR{D,SB,H,SH})
pub const R_ARM_THM_PC12: u32 = 54;
/// Direct 32-bit
pub const R_ARM_ABS32_NOI: u32 = 55;
/// PC relative 32-bit
pub const R_ARM_REL32_NOI: u32 = 56;
/// PC relative (ADD, SUB)
pub const R_ARM_ALU_PC_G0_NC: u32 = 57;
/// PC relative (ADD, SUB)
pub const R_ARM_ALU_PC_G0: u32 = 58;
/// PC relative (ADD, SUB)
pub const R_ARM_ALU_PC_G1_NC: u32 = 59;
/// PC relative (ADD, SUB)
pub const R_ARM_ALU_PC_G1: u32 = 60;
/// PC relative (ADD, SUB)
pub const R_ARM_ALU_PC_G2: u32 = 61;
/// PC relative (LDR,STR,LDRB,STRB)
pub const R_ARM_LDR_PC_G1: u32 = 62;
/// PC relative (LDR,STR,LDRB,STRB)
pub const R_ARM_LDR_PC_G2: u32 = 63;
/// PC relative (STR{D,H},LDR{D,SB,H,SH})
pub const R_ARM_LDRS_PC_G0: u32 = 64;
/// PC relative (STR{D,H},LDR{D,SB,H,SH})
pub const R_ARM_LDRS_PC_G1: u32 = 65;
/// PC relative (STR{D,H},LDR{D,SB,H,SH})
pub const R_ARM_LDRS_PC_G2: u32 = 66;
/// PC relative (LDC, STC)
pub const R_ARM_LDC_PC_G0: u32 = 67;
/// PC relative (LDC, STC)
pub const R_ARM_LDC_PC_G1: u32 = 68;
/// PC relative (LDC, STC)
pub const R_ARM_LDC_PC_G2: u32 = 69;
/// Program base relative (ADD,SUB)
pub const R_ARM_ALU_SB_G0_NC: u32 = 70;
/// Program base relative (ADD,SUB)
pub const R_ARM_ALU_SB_G0: u32 = 71;
/// Program base relative (ADD,SUB)
pub const R_ARM_ALU_SB_G1_NC: u32 = 72;
/// Program base relative (ADD,SUB)
pub const R_ARM_ALU_SB_G1: u32 = 73;
/// Program base relative (ADD,SUB)
pub const R_ARM_ALU_SB_G2: u32 = 74;
/// Program base relative (LDR,STR, LDRB, STRB)
pub const R_ARM_LDR_SB_G0: u32 = 75;
/// Program base relative (LDR, STR, LDRB, STRB)
pub const R_ARM_LDR_SB_G1: u32 = 76;
/// Program base relative (LDR, STR, LDRB, STRB)
pub const R_ARM_LDR_SB_G2: u32 = 77;
/// Program base relative (LDR, STR, LDRB, STRB)
pub const R_ARM_LDRS_SB_G0: u32 = 78;
/// Program base relative (LDR, STR, LDRB, STRB)
pub const R_ARM_LDRS_SB_G1: u32 = 79;
/// Program base relative (LDR, STR, LDRB, STRB)
pub const R_ARM_LDRS_SB_G2: u32 = 80;
/// Program base relative (LDC,STC)
pub const R_ARM_LDC_SB_G0: u32 = 81;
/// Program base relative (LDC,STC)
pub const R_ARM_LDC_SB_G1: u32 = 82;
/// Program base relative (LDC,STC)
pub const R_ARM_LDC_SB_G2: u32 = 83;
/// Program base relative 16 bit (MOVW)
pub const R_ARM_MOVW_BREL_NC: u32 = 84;
/// Program base relative high 16 bit (MOVT)
pub const R_ARM_MOVT_BREL: u32 = 85;
/// Program base relative 16 bit (MOVW)
pub const R_ARM_MOVW_BREL: u32 = 86;
/// Program base relative 16 bit (Thumb32 MOVW)
pub const R_ARM_THM_MOVW_BREL_NC: u32 = 87;
/// Program base relative high 16 bit (Thumb32 MOVT)
pub const R_ARM_THM_MOVT_BREL: u32 = 88;
/// Program base relative 16 bit (Thumb32 MOVW)
pub const R_ARM_THM_MOVW_BREL: u32 = 89;
pub const R_ARM_TLS_GOTDESC: u32 = 90;
pub const R_ARM_TLS_CALL: u32 = 91;
/// TLS relaxation
pub const R_ARM_TLS_DESCSEQ: u32 = 92;
pub const R_ARM_THM_TLS_CALL: u32 = 93;
pub const R_ARM_PLT32_ABS: u32 = 94;
/// GOT entry
pub const R_ARM_GOT_ABS: u32 = 95;
/// PC relative GOT entry
pub const R_ARM_GOT_PREL: u32 = 96;
/// GOT entry relative to GOT origin (LDR)
pub const R_ARM_GOT_BREL12: u32 = 97;
/// 12 bit, GOT entry relative to GOT origin (LDR, STR)
pub const R_ARM_GOTOFF12: u32 = 98;
pub const R_ARM_GOTRELAX: u32 = 99;
pub const R_ARM_GNU_VTENTRY: u32 = 100;
pub const R_ARM_GNU_VTINHERIT: u32 = 101;
/// PC relative & 0xFFE (Thumb16 B)
pub const R_ARM_THM_PC11: u32 = 102;
/// PC relative & 0x1FE (Thumb16 B/B<cond>)
pub const R_ARM_THM_PC9: u32 = 103;
/// PC-rel 32 bit for global dynamic thread local data
pub const R_ARM_TLS_GD32: u32 = 104;
/// PC-rel 32 bit for local dynamic thread local data
pub const R_ARM_TLS_LDM32: u32 = 105;
/// 32 bit offset relative to TLS block
pub const R_ARM_TLS_LDO32: u32 = 106;
/// PC-rel 32 bit for GOT entry of static TLS block offset
pub const R_ARM_TLS_IE32: u32 = 107;
/// 32 bit offset relative to static TLS block
pub const R_ARM_TLS_LE32: u32 = 108;
/// 12 bit relative to TLS block (LDR, STR)
pub const R_ARM_TLS_LDO12: u32 = 109;
/// 12 bit relative to static TLS block (LDR, STR)
pub const R_ARM_TLS_LE12: u32 = 110;
/// 12 bit GOT entry relative to GOT origin (LDR)
pub const R_ARM_TLS_IE12GP: u32 = 111;
/// Obsolete
pub const R_ARM_ME_TOO: u32 = 128;
pub const R_ARM_THM_TLS_DESCSEQ: u32 = 129;
pub const R_ARM_THM_TLS_DESCSEQ16: u32 = 129;
pub const R_ARM_THM_TLS_DESCSEQ32: u32 = 130;
/// GOT entry relative to GOT origin, 12 bit (Thumb32 LDR)
pub const R_ARM_THM_GOT_BREL12: u32 = 131;
pub const R_ARM_IRELATIVE: u32 = 160;
pub const R_ARM_RXPC25: u32 = 249;
pub const R_ARM_RSBREL32: u32 = 250;
pub const R_ARM_THM_RPC22: u32 = 251;
pub const R_ARM_RREL32: u32 = 252;
pub const R_ARM_RABS22: u32 = 253;
pub const R_ARM_RPC24: u32 = 254;
pub const R_ARM_RBASE: u32 = 255;
/// Keep this the last entry
pub const R_ARM_NUM: u32 = 	256;
