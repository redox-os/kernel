//! See <https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#system-resource-affinity-table-srat>

use crate::{
    acpi::{find_sdt, sdt::Sdt, srat},
    find_one_sdt,
    numa::{NUMA_NODES, NUMBER_OF_DOMAINS},
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

pub fn init() {
    let srat = Srat::new(find_one_sdt!("SRAT"));
    arch::init_srat(&srat);
    NUMBER_OF_DOMAINS.call_once(|| NUMA_NODES.get().unwrap().len() as u32);
}

impl Srat {
    pub fn new(sdt: &'static Sdt) -> Self {
        Self {
            sdt,
            entries: sdt.data_address() + 12,
        }
    }
}

impl<'a> IntoIterator for &'a Srat {
    type Item = SratEntry;

    type IntoIter = SratIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SratIter { i: 0, srat: self }
    }
}

pub struct SratIter<'a> {
    i: u32,
    srat: &'a Srat,
}

impl<'a> Iterator for SratIter<'a> {
    type Item = SratEntry;

    fn next(&mut self) -> Option<Self::Item> {
        while self.i < self.srat.sdt.data_len() as u32 {
            let entry = (self.srat.entries + self.i as usize) as *const u8;
            let entry_len = unsafe { *((self.srat.entries + self.i as usize + 1) as *const u8) };

            let entry = Some(match unsafe { *entry } {
                0 => SratEntry::LegacyProcessorLocalAffinity(unsafe {
                    assert!(entry_len as usize == size_of::<LegacyProcessorLocalAffinity>() + 2);
                    *(entry.add(2) as *const LegacyProcessorLocalAffinity)
                }),

                1 => SratEntry::MemoryAffinity(unsafe {
                    assert!(entry_len as usize == size_of::<MemoryAffinity>() + 10);
                    *(entry.add(2) as *const MemoryAffinity)
                }),
                2 => SratEntry::ProcessorLocalAffinity(unsafe {
                    assert!(entry_len as usize == size_of::<ProcessorLocalAffinity>() + 8);
                    *(entry.add(4) as *const ProcessorLocalAffinity)
                }),
                3 => SratEntry::GiccAffinity(unsafe {
                    assert!(entry_len as usize == size_of::<GiccAffinity>() + 2);
                    *(entry.add(2) as *const GiccAffinity)
                }),
                // ignore ITS Affinity and Generic Initiator Affinity
                4 | 5 => {
                    self.i += entry_len as u32;
                    continue;
                }
                _ => SratEntry::Unknown(unsafe { *entry }),
            });
            self.i += entry_len as u32;
            return entry;
        }
        None
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SratEntry {
    LegacyProcessorLocalAffinity(LegacyProcessorLocalAffinity),
    MemoryAffinity(MemoryAffinity),
    ProcessorLocalAffinity(ProcessorLocalAffinity),
    GiccAffinity(GiccAffinity),
    Unknown(u8), // unimplemented: Generic Initiator Affinity; our current focus is only on memory and cpus
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
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
#[derive(Clone, Copy, Debug)]
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
#[derive(Clone, Copy, Debug)]
/// For x2APIC systems
struct ProcessorLocalAffinity {
    proximity_domain: u32,
    x2apic_id: u32,
    flags: u32,
    clock_domain: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct GiccAffinity {
    proximity_domain: u32,
    processor_uid: u32,
    flags: u32,
    clock_domain: u32,
}
