use core::fmt::{Result, Write};

use crate::device::cpu::registers::{control_regs};

pub mod registers;

bitfield! {
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
    Infineon,
    Motorola,
    Nvidia,
    AMCC,
    Qualcomm,
    Marvell,
    Intel,
}

const IMPLEMENTERS: [&'static str; 12] = [
    "Unknown",
    "Arm",
    "Broadcom",
    "Cavium",
    "Digital",
    "Infineon",
    "Motorola",
    "Nvidia",
    "AMCC",
    "Qualcomm",
    "Marvell",
    "Intel",
];


enum VariantID {
    Unknown,
}

const VARIANTS: [&'static str; 1] = [
    "Unknown",
];

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

const ARCHITECTURES: [&'static str; 8] = [
    "Unknown",
    "v4",
    "v4T",
    "v5",
    "v5T",
    "v5TE",
    "v5TEJ",
    "v6",
];

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

const REVISIONS: [&'static str; 3] = [
    "Unknown",
    "Thunder-1.0",
    "Thunder-1.1",
];

struct CpuInfo {
    implementer: &'static str,
    variant: &'static str,
    architecture: &'static str,
    part_number: &'static str,
    revision: &'static str,
}

impl CpuInfo {
    fn new() -> CpuInfo {
        let midr = unsafe { control_regs::midr() };
        println!("MIDR: 0x{:x}", midr);
        let midr = MachineId(midr);

        let implementer = match midr.get_implementer() {
            0x41 => IMPLEMENTERS[ImplementerID::Arm as usize],
            0x42 => IMPLEMENTERS[ImplementerID::Broadcom as usize],
            0x43 => IMPLEMENTERS[ImplementerID::Cavium as usize],
            0x44 => IMPLEMENTERS[ImplementerID::Digital as usize],
            0x49 => IMPLEMENTERS[ImplementerID::Infineon as usize],
            0x4d => IMPLEMENTERS[ImplementerID::Motorola as usize],
            0x4e => IMPLEMENTERS[ImplementerID::Nvidia as usize],
            0x50 => IMPLEMENTERS[ImplementerID::AMCC as usize],
            0x51 => IMPLEMENTERS[ImplementerID::Qualcomm as usize],
            0x56 => IMPLEMENTERS[ImplementerID::Marvell as usize],
            0x69 => IMPLEMENTERS[ImplementerID::Intel as usize],
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
            },
            _ => REVISIONS[RevisionID::Unknown as usize],
        };

        CpuInfo {
            implementer,
            variant,
            architecture,
            part_number,
            revision,
        }
    }
}

pub fn cpu_info<W: Write>(w: &mut W) -> Result {
    let cpuinfo = CpuInfo::new();

    write!(w, "Implementer: {}\n", cpuinfo.implementer)?;
    write!(w, "Variant: {}\n", cpuinfo.variant)?;
    write!(w, "Architecture version: {}\n", cpuinfo.architecture)?;
    write!(w, "Part Number: {}\n", cpuinfo.part_number)?;
    write!(w, "Revision: {}\n", cpuinfo.revision)?;
    write!(w, "\n")?;

    Ok(())
}
