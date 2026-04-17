use core::fmt::{Result, Write};

use crate::arch::device::cpu::registers::{control_regs, id_regs};

pub mod registers;

bitfield::bitfield! {
    pub struct MachineId(u32);
    get_implementer, _: 31, 24;
    get_variant, _: 23, 20;
    get_architecture, _: 19, 16;
    get_part_number, _: 15, 4;
    get_revision, _: 3, 0;
}

enum ImplementerID {
    Unknown,
    Arm,
    Broadcom,
    Cavium,
    Digital,
    Fujitsu,
    Infineon,
    Motorola,
    Nvidia,
    AMCC,
    Qualcomm,
    Marvell,
    Intel,
    Ampere,
}

const IMPLEMENTERS: [&'static str; 14] = [
    "Unknown", "Arm", "Broadcom", "Cavium", "Digital", "Fujitsu", "Infineon", "Motorola", "Nvidia",
    "AMCC", "Qualcomm", "Marvell", "Intel", "Ampere",
];

enum VariantID {
    Unknown,
}

const VARIANTS: [&'static str; 1] = ["Unknown"];

enum ArchitectureID {
    Unknown,
    V4,
    V4T,
    V5,
    V5T,
    V5TE,
    V5TEJ,
    V6,
}

const ARCHITECTURES: [&'static str; 8] =
    ["Unknown", "v4", "v4T", "v5", "v5T", "v5TE", "v5TEJ", "v6"];

enum PartNumberID {
    Unknown,
    Thunder,
    Foundation,
    CortexA35,
    CortexA53,
    CortexA55,
    CortexA57,
    CortexA72,
    CortexA73,
    CortexA75,
}

const PART_NUMBERS: [&'static str; 10] = [
    "Unknown",
    "Thunder",
    "Foundation",
    "Cortex-A35",
    "Cortex-A53",
    "Cortex-A55",
    "Cortex-A57",
    "Cortex-A72",
    "Cortex-A73",
    "Cortex-A75",
];

enum RevisionID {
    Unknown,
    Thunder1_0,
    Thunder1_1,
}

const REVISIONS: [&'static str; 3] = ["Unknown", "Thunder-1.0", "Thunder-1.1"];

struct CpuInfo {
    implementer: &'static str,
    variant: &'static str,
    architecture: &'static str,
    part_number: &'static str,
    revision: &'static str,
    aa64isar0: id_regs::AA64Isar0,
    aa64isar1: id_regs::AA64Isar1,
}

impl CpuInfo {
    fn new() -> CpuInfo {
        let midr = unsafe { control_regs::midr() };
        let midr = MachineId(midr);

        let implementer = match midr.get_implementer() {
            0x41 => IMPLEMENTERS[ImplementerID::Arm as usize],
            0x42 => IMPLEMENTERS[ImplementerID::Broadcom as usize],
            0x43 => IMPLEMENTERS[ImplementerID::Cavium as usize],
            0x44 => IMPLEMENTERS[ImplementerID::Digital as usize],
            0x46 => IMPLEMENTERS[ImplementerID::Fujitsu as usize],
            0x49 => IMPLEMENTERS[ImplementerID::Infineon as usize],
            0x4d => IMPLEMENTERS[ImplementerID::Motorola as usize],
            0x4e => IMPLEMENTERS[ImplementerID::Nvidia as usize],
            0x50 => IMPLEMENTERS[ImplementerID::AMCC as usize],
            0x51 => IMPLEMENTERS[ImplementerID::Qualcomm as usize],
            0x56 => IMPLEMENTERS[ImplementerID::Marvell as usize],
            0x69 => IMPLEMENTERS[ImplementerID::Intel as usize],
            0xc0 => IMPLEMENTERS[ImplementerID::Ampere as usize],
            _ => IMPLEMENTERS[ImplementerID::Unknown as usize],
        };

        let variant = match midr.get_variant() {
            _ => VARIANTS[VariantID::Unknown as usize],
        };

        let architecture = match midr.get_architecture() {
            0b0001 => ARCHITECTURES[ArchitectureID::V4 as usize],
            0b0010 => ARCHITECTURES[ArchitectureID::V4T as usize],
            0b0011 => ARCHITECTURES[ArchitectureID::V5 as usize],
            0b0100 => ARCHITECTURES[ArchitectureID::V5T as usize],
            0b0101 => ARCHITECTURES[ArchitectureID::V5TE as usize],
            0b0110 => ARCHITECTURES[ArchitectureID::V5TEJ as usize],
            0b0111 => ARCHITECTURES[ArchitectureID::V6 as usize],
            _ => ARCHITECTURES[ArchitectureID::Unknown as usize],
        };

        let part_number = match midr.get_part_number() {
            0x0a1 => PART_NUMBERS[PartNumberID::Thunder as usize],
            0xd00 => PART_NUMBERS[PartNumberID::Foundation as usize],
            0xd04 => PART_NUMBERS[PartNumberID::CortexA35 as usize],
            0xd03 => PART_NUMBERS[PartNumberID::CortexA53 as usize],
            0xd05 => PART_NUMBERS[PartNumberID::CortexA55 as usize],
            0xd07 => PART_NUMBERS[PartNumberID::CortexA57 as usize],
            0xd08 => PART_NUMBERS[PartNumberID::CortexA72 as usize],
            0xd09 => PART_NUMBERS[PartNumberID::CortexA73 as usize],
            0xd0a => PART_NUMBERS[PartNumberID::CortexA75 as usize],
            _ => PART_NUMBERS[PartNumberID::Unknown as usize],
        };

        let revision = match part_number {
            "Thunder" => {
                let val = match midr.get_revision() {
                    0x00 => REVISIONS[RevisionID::Thunder1_0 as usize],
                    0x01 => REVISIONS[RevisionID::Thunder1_1 as usize],
                    _ => REVISIONS[RevisionID::Unknown as usize],
                };
                val
            }
            _ => REVISIONS[RevisionID::Unknown as usize],
        };

        let aa64isar0 = id_regs::aa64isar0();
        let aa64isar1 = id_regs::aa64isar1();

        CpuInfo {
            implementer,
            variant,
            architecture,
            part_number,
            revision,
            aa64isar0,
            aa64isar1,
        }
    }
}

pub fn cpu_info<W: Write>(w: &mut W) -> Result {
    let cpuinfo = CpuInfo::new();

    writeln!(w, "Implementer: {}", cpuinfo.implementer)?;
    writeln!(w, "Variant: {}", cpuinfo.variant)?;
    writeln!(w, "Architecture version: {}", cpuinfo.architecture)?;
    writeln!(w, "Part Number: {}", cpuinfo.part_number)?;
    writeln!(w, "Revision: {}", cpuinfo.revision)?;

    // Print detected CPU features.
    // Follow the naming convention estabilished by `std::arch::is_aarch64_feature_detected`.
    write!(w, "Features:")?;

    // ID_AA64ISAR0_EL1
    if cpuinfo.aa64isar0.has_feat_rng() {
        write!(w, " rand")?;
    }
    if cpuinfo.aa64isar0.has_feat_flagm() {
        write!(w, " flagm")?;
    }
    if cpuinfo.aa64isar0.has_feat_flagm2() {
        write!(w, " flagm2")?;
    }
    if cpuinfo.aa64isar0.has_feat_fhm() {
        write!(w, " fhm")?;
    }
    if cpuinfo.aa64isar0.has_feat_dotprod() {
        write!(w, " dotprod")?;
    }
    if cpuinfo.aa64isar0.has_feat_sm3() && cpuinfo.aa64isar0.has_feat_sm4() {
        write!(w, " sm4")?;
    }
    if cpuinfo.aa64isar0.has_feat_sha512() && cpuinfo.aa64isar0.has_feat_sha3() {
        write!(w, " sha3")?;
    }
    if cpuinfo.aa64isar0.has_feat_rdm() {
        write!(w, " rdm")?;
    }
    if cpuinfo.aa64isar0.has_feat_lse() {
        write!(w, " lse")?;
    }
    if cpuinfo.aa64isar0.has_feat_lse128() {
        write!(w, " lse128")?;
    }
    if cpuinfo.aa64isar0.has_feat_crc() {
        write!(w, " crc")?;
    }
    if cpuinfo.aa64isar0.has_feat_sha1() && cpuinfo.aa64isar0.has_feat_sha256() {
        write!(w, " sha2")?;
    }
    if cpuinfo.aa64isar0.has_feat_aes() && cpuinfo.aa64isar0.has_feat_pmull() {
        write!(w, " aes")?;
    }

    // ID_AA64ISAR1_EL1
    if cpuinfo.aa64isar1.has_feat_i8mm() {
        write!(w, " i8mm")?;
    }
    if cpuinfo.aa64isar1.has_feat_bf16() {
        write!(w, " bf16")?;
    }
    if cpuinfo.aa64isar1.has_feat_sb() {
        write!(w, " sb")?;
    }
    if cpuinfo.aa64isar1.has_feat_frintts() {
        write!(w, " frintts")?;
    }
    if cpuinfo.aa64isar1.gpi() != 0 || cpuinfo.aa64isar1.gpa() != 0 {
        write!(w, " pacg")?;
    }
    if cpuinfo.aa64isar1.has_feat_lrcpc() {
        write!(w, " rcpc")?;
    }
    if cpuinfo.aa64isar1.has_feat_lrcpc2() {
        write!(w, " rcpc2")?;
    }
    if cpuinfo.aa64isar1.has_feat_lrcpc3() {
        write!(w, " rcpc3")?;
    }
    if cpuinfo.aa64isar1.has_feat_fcma() {
        write!(w, " fcma")?;
    }
    if cpuinfo.aa64isar1.has_feat_jscvt() {
        write!(w, " jsconv")?;
    }
    if cpuinfo.aa64isar1.api() != 0 || cpuinfo.aa64isar1.apa() != 0 {
        write!(w, " paca")?;
    }
    if cpuinfo.aa64isar1.has_feat_dpb() {
        write!(w, " dpb")?;
    }
    if cpuinfo.aa64isar1.has_feat_dpb2() {
        write!(w, " dpb2")?;
    }

    writeln!(w)?;

    Ok(())
}
