// sweet emacs regexp
// pub const \([[:word:]|_]*\)[[:space:]]*\([[:digit:]]+\)[[:space:]]*/\*\(.*\) \*/
// \\\\3 C-q C-j pub const \1: u32 = \2;

/// TODO: use Enum with explicit discriminant and get debug printer for free?

/// No machine
pub const EM_NONE: u16 = 0;
/// AT&T WE 32100
pub const EM_M32: u16 = 1;
/// SUN SPARC
pub const EM_SPARC: u16 = 2;
/// Intel 80386
pub const EM_386: u16 = 3;
/// Motorola m68k family
pub const EM_68K: u16 = 4;
/// Motorola m88k family
pub const EM_88K: u16 = 5;
/// Intel MCU
pub const EM_IAMCU: u16 = 6;
/// Intel 80860
pub const EM_860: u16 = 7;
/// MIPS R3000 big-endian
pub const EM_MIPS: u16 = 8;
/// IBM System/370
pub const EM_S370: u16 = 9;
/// MIPS R3000 little-endian
pub const EM_MIPS_RS3_LE: u16 = 10;
// reserved 11-14
/// HPPA
pub const EM_PARISC: u16 = 15;
// reserved 16
/// Fujitsu VPP500
pub const EM_VPP500: u16 = 17;
/// Sun's "v8plus"
pub const EM_SPARC32PLUS: u16 = 18;
/// Intel 80960
pub const EM_960: u16 = 19;
/// PowerPC
pub const EM_PPC: u16 = 20;
/// PowerPC 64-bit
pub const EM_PPC64: u16 = 21;
/// IBM S390
pub const EM_S390: u16 = 22;
/// IBM SPU/SPC
pub const EM_SPU: u16 = 23;
// reserved 24-35
/// NEC V800 series
pub const EM_V800: u16 = 36;
/// Fujitsu FR20
pub const EM_FR20: u16 = 37;
/// TRW RH-32
pub const EM_RH32: u16 = 38;
/// Motorola RCE
pub const EM_RCE: u16 = 39;
/// ARM
pub const EM_ARM: u16 = 40;
/// Digital Alpha
pub const EM_FAKE_ALPHA: u16 = 41;
/// Hitachi SH
pub const EM_SH: u16 = 42;
/// SPARC v9 64-bit
pub const EM_SPARCV9: u16 = 43;
/// Siemens Tricore
pub const EM_TRICORE: u16 = 44;
/// Argonaut RISC Core
pub const EM_ARC: u16 = 45;
/// Hitachi H8/300
pub const EM_H8_300: u16 = 46;
/// Hitachi H8/300H
pub const EM_H8_300H: u16 = 47;
/// Hitachi H8S
pub const EM_H8S: u16 = 48;
/// Hitachi H8/500
pub const EM_H8_500: u16 = 49;
/// Intel Merced
pub const EM_IA_64: u16 = 50;
/// Stanford MIPS-X
pub const EM_MIPS_X: u16 = 51;
/// Motorola Coldfire
pub const EM_COLDFIRE: u16 = 52;
/// Motorola M68HC12
pub const EM_68HC12: u16 = 53;
/// Fujitsu MMA Multimedia Accelerator
pub const EM_MMA: u16 = 54;
/// Siemens PCP
pub const EM_PCP: u16 = 55;
/// Sony nCPU embeeded RISC
pub const EM_NCPU: u16 = 56;
/// Denso NDR1 microprocessor
pub const EM_NDR1: u16 = 57;
/// Motorola Start*Core processor
pub const EM_STARCORE: u16 = 58;
/// Toyota ME16 processor
pub const EM_ME16: u16 = 59;
/// STMicroelectronic ST100 processor
pub const EM_ST100: u16 = 60;
/// Advanced Logic Corp. Tinyj emb.fam
pub const EM_TINYJ: u16 = 61;
/// AMD x86-64 architecture
pub const EM_X86_64: u16 = 62;
/// Sony DSP Processor
pub const EM_PDSP: u16 = 63;
/// Digital PDP-10
pub const EM_PDP10: u16 = 64;
/// Digital PDP-11
pub const EM_PDP11: u16 = 65;
/// Siemens FX66 microcontroller
pub const EM_FX66: u16 = 66;
/// STMicroelectronics ST9+ 8/16 mc
pub const EM_ST9PLUS: u16 = 67;
/// STmicroelectronics ST7 8 bit mc
pub const EM_ST7: u16 = 68;
/// Motorola MC68HC16 microcontroller
pub const EM_68HC16: u16 = 69;
/// Motorola MC68HC11 microcontroller
pub const EM_68HC11: u16 = 70;
/// Motorola MC68HC08 microcontroller
pub const EM_68HC08: u16 = 71;
/// Motorola MC68HC05 microcontroller
pub const EM_68HC05: u16 = 72;
/// Silicon Graphics SVx
pub const EM_SVX: u16 = 73;
/// STMicroelectronics ST19 8 bit mc
pub const EM_ST19: u16 = 74;
/// Digital VAX
pub const EM_VAX: u16 = 75;
/// Axis Communications 32-bit emb.proc
pub const EM_CRIS: u16 = 76;
/// Infineon Technologies 32-bit emb.proc
pub const EM_JAVELIN: u16 = 77;
/// Element 14 64-bit DSP Processor
pub const EM_FIREPATH: u16 = 78;
/// LSI Logic 16-bit DSP Processor
pub const EM_ZSP: u16 = 79;
/// Donald Knuth's educational 64-bit proc
pub const EM_MMIX: u16 = 80;
/// Harvard University machine-independent object files
pub const EM_HUANY: u16 = 81;
/// SiTera Prism
pub const EM_PRISM: u16 = 82;
/// Atmel AVR 8-bit microcontroller
pub const EM_AVR: u16 = 83;
/// Fujitsu FR30
pub const EM_FR30: u16 = 84;
/// Mitsubishi D10V
pub const EM_D10V: u16 = 85;
/// Mitsubishi D30V
pub const EM_D30V: u16 = 86;
/// NEC v850
pub const EM_V850: u16 = 87;
/// Mitsubishi M32R
pub const EM_M32R: u16 = 88;
/// Matsushita MN10300
pub const EM_MN10300: u16 = 89;
/// Matsushita MN10200
pub const EM_MN10200: u16 = 90;
/// picoJava
pub const EM_PJ: u16 = 91;
/// OpenRISC 32-bit embedded processor
pub const EM_OPENRISC: u16 = 92;
/// ARC International ARCompact
pub const EM_ARC_COMPACT: u16 = 93;
/// Tensilica Xtensa Architecture
pub const EM_XTENSA: u16 = 94;
/// Alphamosaic VideoCore
pub const EM_VIDEOCORE: u16 = 95;
/// Thompson Multimedia General Purpose Proc
pub const EM_TMM_GPP: u16 = 96;
/// National Semi. 32000
pub const EM_NS32K: u16 = 97;
/// Tenor Network TPC
pub const EM_TPC: u16 = 98;
/// Trebia SNP 1000
pub const EM_SNP1K: u16 = 99;
/// STMicroelectronics ST200
pub const EM_ST200: u16 = 100;
/// Ubicom IP2xxx
pub const EM_IP2K: u16 = 101;
/// MAX processor
pub const EM_MAX: u16 = 102;
/// National Semi. CompactRISC
pub const EM_CR: u16 = 103;
/// Fujitsu F2MC16
pub const EM_F2MC16: u16 = 104;
/// Texas Instruments msp430
pub const EM_MSP430: u16 = 105;
/// Analog Devices Blackfin DSP
pub const EM_BLACKFIN: u16 = 106;
/// Seiko Epson S1C33 family
pub const EM_SE_C33: u16 = 107;
/// Sharp embedded microprocessor
pub const EM_SEP: u16 = 108;
/// Arca RISC
pub const EM_ARCA: u16 = 109;
/// PKU-Unity & MPRC Peking Uni. mc series
pub const EM_UNICORE: u16 = 110;
/// eXcess configurable cpu
pub const EM_EXCESS: u16 = 111;
/// Icera Semi. Deep Execution Processor
pub const EM_DXP: u16 = 112;
/// Altera Nios II
pub const EM_ALTERA_NIOS2: u16 = 113;
/// National Semi. CompactRISC CRX
pub const EM_CRX: u16 = 114;
/// Motorola XGATE
pub const EM_XGATE: u16 = 115;
/// Infineon C16x/XC16x
pub const EM_C166: u16 = 116;
/// Renesas M16C
pub const EM_M16C: u16 = 117;
/// Microchip Technology dsPIC30F
pub const EM_DSPIC30F: u16 = 118;
/// Freescale Communication Engine RISC
pub const EM_CE: u16 = 119;
/// Renesas M32C
pub const EM_M32C: u16 = 120;
// reserved 121-130
/// Altium TSK3000
pub const EM_TSK3000: u16 = 131;
/// Freescale RS08
pub const EM_RS08: u16 = 132;
/// Analog Devices SHARC family
pub const EM_SHARC: u16 = 133;
/// Cyan Technology eCOG2
pub const EM_ECOG2: u16 = 134;
/// Sunplus S+core7 RISC
pub const EM_SCORE7: u16 = 135;
/// New Japan Radio (NJR) 24-bit DSP
pub const EM_DSP24: u16 = 136;
/// Broadcom VideoCore III
pub const EM_VIDEOCORE3: u16 = 137;
/// RISC for Lattice FPGA
pub const EM_LATTICEMICO32: u16 = 138;
/// Seiko Epson C17
pub const EM_SE_C17: u16 = 139;
/// Texas Instruments TMS320C6000 DSP
pub const EM_TI_C6000: u16 = 140;
/// Texas Instruments TMS320C2000 DSP
pub const EM_TI_C2000: u16 = 141;
/// Texas Instruments TMS320C55x DSP
pub const EM_TI_C5500: u16 = 142;
/// Texas Instruments App. Specific RISC
pub const EM_TI_ARP32: u16 = 143;
/// Texas Instruments Prog. Realtime Unit
pub const EM_TI_PRU: u16 = 144;
// reserved 145-159
/// STMicroelectronics 64bit VLIW DSP
pub const EM_MMDSP_PLUS: u16 = 160;
/// Cypress M8C
pub const EM_CYPRESS_M8C: u16 = 161;
/// Renesas R32C
pub const EM_R32C: u16 = 162;
/// NXP Semi. TriMedia
pub const EM_TRIMEDIA: u16 = 163;
/// QUALCOMM DSP6
pub const EM_QDSP6: u16 = 164;
/// Intel 8051 and variants
pub const EM_8051: u16 = 165;
/// STMicroelectronics STxP7x
pub const EM_STXP7X: u16 = 166;
/// Andes Tech. compact code emb. RISC
pub const EM_NDS32: u16 = 167;
/// Cyan Technology eCOG1X
pub const EM_ECOG1X: u16 = 168;
/// Dallas Semi. MAXQ30 mc
pub const EM_MAXQ30: u16 = 169;
/// New Japan Radio (NJR) 16-bit DSP
pub const EM_XIMO16: u16 = 170;
/// M2000 Reconfigurable RISC
pub const EM_MANIK: u16 = 171;
/// Cray NV2 vector architecture
pub const EM_CRAYNV2: u16 = 172;
/// Renesas RX
pub const EM_RX: u16 = 173;
/// Imagination Tech. META
pub const EM_METAG: u16 = 174;
/// MCST Elbrus
pub const EM_MCST_ELBRUS: u16 = 175;
/// Cyan Technology eCOG16
pub const EM_ECOG16: u16 = 176;
/// National Semi. CompactRISC CR16
pub const EM_CR16: u16 = 177;
/// Freescale Extended Time Processing Unit
pub const EM_ETPU: u16 = 178;
/// Infineon Tech. SLE9X
pub const EM_SLE9X: u16 = 179;
/// Intel L10M
pub const EM_L10M: u16 = 180;
/// Intel K10M
pub const EM_K10M: u16 = 181;
// reserved 182
/// ARM AARCH64
pub const EM_AARCH64: u16 = 183;
// reserved 184
/// Amtel 32-bit microprocessor
pub const EM_AVR32: u16 = 185;
/// STMicroelectronics STM8
pub const EM_STM8: u16 = 186;
/// Tileta TILE64
pub const EM_TILE64: u16 = 187;
/// Tilera TILEPro
pub const EM_TILEPRO: u16 = 188;
/// Xilinx MicroBlaze
pub const EM_MICROBLAZE: u16 = 189;
/// NVIDIA CUDA
pub const EM_CUDA: u16 = 190;
/// Tilera TILE-Gx
pub const EM_TILEGX: u16 = 191;
/// CloudShield
pub const EM_CLOUDSHIELD: u16 = 192;
/// KIPO-KAIST Core-A 1st gen.
pub const EM_COREA_1ST: u16 = 193;
/// KIPO-KAIST Core-A 2nd gen.
pub const EM_COREA_2ND: u16 = 194;
/// Synopsys ARCompact V2
pub const EM_ARC_COMPACT2: u16 = 195;
/// Open8 RISC
pub const EM_OPEN8: u16 = 196;
/// Renesas RL78
pub const EM_RL78: u16 = 197;
/// Broadcom VideoCore V
pub const EM_VIDEOCORE5: u16 = 198;
/// Renesas 78KOR
pub const EM_78KOR: u16 = 199;
/// Freescale 56800EX DSC
pub const EM_56800EX: u16 = 200;
/// Beyond BA1
pub const EM_BA1: u16 = 201;
/// Beyond BA2
pub const EM_BA2: u16 = 202;
/// XMOS xCORE
pub const EM_XCORE: u16 = 203;
/// Microchip 8-bit PIC(r)
pub const EM_MCHP_PIC: u16 = 204;
// reserved 205-209
/// KM211 KM32
pub const EM_KM32: u16 = 210;
/// KM211 KMX32
pub const EM_KMX32: u16 = 211;
/// KM211 KMX16
pub const EM_EMX16: u16 = 212;
/// KM211 KMX8
pub const EM_EMX8: u16 = 213;
/// KM211 KVARC
pub const EM_KVARC: u16 = 214;
/// Paneve CDP
pub const EM_CDP: u16 = 215;
/// Cognitive Smart Memory Processor
pub const EM_COGE: u16 = 216;
/// Bluechip CoolEngine
pub const EM_COOL: u16 = 217;
/// Nanoradio Optimized RISC
pub const EM_NORC: u16 = 218;
/// CSR Kalimba
pub const EM_CSR_KALIMBA: u16 = 219;
/// Zilog Z80
pub const EM_Z80: u16 = 220;
/// Controls and Data Services VISIUMcore
pub const EM_VISIUM: u16 = 221;
/// FTDI Chip FT32
pub const EM_FT32: u16 = 222;
/// Moxie processor
pub const EM_MOXIE: u16 = 223;
/// AMD GPU
pub const EM_AMDGPU: u16 = 224;
// reserved 225-242
/// RISC-V
pub const EM_RISCV: u16 = 243;

/// Linux BPF -- in-kernel virtual machine
pub const EM_BPF: u16 = 247;

pub const EM_NUM: u16 = 248;
