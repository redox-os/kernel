//! See <https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#system-resource-affinity-table-srat>

use crate::{
    acpi::{find_sdt, sdt::Sdt, srat},
    find_one_sdt,
};

#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod arch;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[path = "x86.rs"]
mod arch;

#[repr(C, packed)]
pub struct Srat {
    sdt: &'static Sdt,
    entries: usize,
}

impl Srat {
    pub fn init() {
        let srat = Self::new(find_one_sdt!("SRAT"));
        arch::init_srat(&srat);
    }

    pub fn new(sdt: &'static Sdt) -> Self {
        Self {
            sdt,
            entries: sdt.data_address() + 16,
        }
    }
}

struct SratIter<'a> {
    i: u32,
    srat: &'a Srat,
}

impl<'a> Iterator for SratIter<'a> {
    type Item = SratEntry;

    fn next(&mut self) -> Option<Self::Item> {
        while self.i < self.srat.sdt.length {
            let entry = (self.srat.entries + self.i as usize) as *const u8;

            return Some(match unsafe { *entry } {
                0 => SratEntry::LegacyProcessorLocalAffinity(unsafe {
                    *(entry.add(2) as *const LegacyProcessorLocalAffinity)
                }),

                1 => SratEntry::MemoryAffinity(unsafe { *(entry.add(2) as *const MemoryAffinity) }),
                2 => SratEntry::ProcessorLocalAffinity(unsafe {
                    *(entry.add(4) as *const ProcessorLocalAffinity)
                }),
                3 => SratEntry::GiccAffinity(unsafe { *(entry.add(2) as *const GiccAffinity) }),
                4 => SratEntry::GicItsAffinity(unsafe { *(entry.add(2) as *const GicItsAffinity) }),
                // ignore Generic Initiator Affinity
                5 => {
                    self.i += 1;
                    continue;
                }
                _ => panic!("Unknown value in Srat"),
            });
        }
        None
    }
}

enum SratEntry {
    LegacyProcessorLocalAffinity(LegacyProcessorLocalAffinity),
    MemoryAffinity(MemoryAffinity),
    ProcessorLocalAffinity(ProcessorLocalAffinity),
    GiccAffinity(GiccAffinity),
    GicItsAffinity(GicItsAffinity),
    // unimplemented: Generic Initiator Affinity; our current focus is only on memory and cpus
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
/// For legacy xAPIC systems
struct LegacyProcessorLocalAffinity {
    proximity_domain_low: u8,
    apic_id: u8,
    flags: u32,
    sapic_id: u8,
    proximity_domain_high: [u8; 3],
    clock_domain: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MemoryAffinity {
    proximity_domain: u32,
    _reserved0: u16,
    base_address_low: u32,
    base_address_high: u32,
    length_low: u32,
    length_high: u32,
    _reserved1: u32,
    flags: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
/// For x2APIC systems
struct ProcessorLocalAffinity {
    proximity_domain: u32,
    x2apic_id: u32,
    flags: u32,
    clock_domain: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GiccAffinity {
    proximity_domain: u32,
    processor_uid: u32,
    flags: u32,
    clock_domain: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GicItsAffinity {
    proximity_domain: u32,
    _reserved: u16,
    its_domain: u32,
}
