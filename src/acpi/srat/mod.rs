//! See <https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#system-resource-affinity-table-srat>

use rmm::{Arch, BumpAllocator, FrameAllocator};
use spin::once::Once;

use crate::{
    acpi::{rxsdt::Rxsdt, sdt::Sdt, RXSDT_ENUM},
    cpu_set::MAX_CPU_COUNT,
    memory,
    numa::{self, NumaMemory, NumaNode, NumaNodeID},
};

#[cfg(target_arch = "x86_64")]
#[path = "x86.rs"]
mod arch;

/// Length of the reserved space after the standard SDT header, before subtables.
const SRAT_RESERVED_LEN: usize = 12;

#[repr(C)]
struct NumaInfo {
    dom_node_map: [Option<NumaNodeID>; numa::MAX_DOMAINS],
    cpus: [Option<NumaNodeID>; MAX_CPU_COUNT as usize],
    memories: [Option<NumaMemory>; numa::MAX_MEM_REGIONS],
    _nodes: [Option<NumaNode>; numa::MAX_DOMAINS],
}

#[repr(C, packed)]
pub struct Srat {
    sdt: &'static Sdt,
    entries: *const u8,
}

pub fn init<A: Arch>(
    allocator: &mut BumpAllocator<A>,
    map: &Once<&'static [Option<NumaNodeID>]>,
    once_cpus: &Once<&'static [Option<NumaNodeID>]>,
    mem: &Once<&'static [Option<NumaMemory>]>,
) {
    let numa_info = allocator
        .allocate(rmm::FrameCount::new(
            size_of::<NumaInfo>().div_ceil(A::PAGE_SIZE),
        ))
        .expect("Failed to allocate memory for storing NUMA info");

    let numa_info = crate::memory::RmmA::phys_to_virt(numa_info).data() as *mut NumaInfo;
    let NumaInfo {
        dom_node_map,
        cpus,
        memories,
        _nodes: _,
    } = unsafe { &mut *numa_info };

    dom_node_map.fill(None);
    cpus.fill(None);
    memories.fill(None);

    if let Some(rxsdt) = RXSDT_ENUM.get() {
        for sdt_addr in rxsdt.iter() {
            let sdt = unsafe { &*(memory::RmmA::phys_to_virt(sdt_addr).data() as *const Sdt) };
            if &sdt.signature == b"SRAT" {
                arch::init_srat(dom_node_map, cpus, memories, &Srat::new(sdt));
                map.call_once(|| dom_node_map);
                once_cpus.call_once(|| cpus);
                mem.call_once(|| memories);
                return;
            }
        }
    }
}

impl Srat {
    pub fn new(sdt: &'static Sdt) -> Self {
        Self {
            sdt,
            entries: sdt.data_address() as *const u8,
        }
    }
}

impl<'a> IntoIterator for &'a Srat {
    type Item = SratEntry;

    type IntoIter = SratIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SratIter {
            i: SRAT_RESERVED_LEN,
            srat: self,
        }
    }
}

pub struct SratIter<'a> {
    i: usize,
    srat: &'a Srat,
}

impl<'a> Iterator for SratIter<'a> {
    type Item = SratEntry;

    fn next(&mut self) -> Option<Self::Item> {
        while self.i < self.srat.sdt.data_len() {
            let entry = unsafe { self.srat.entries.add(self.i) };
            let entry_len = unsafe { *self.srat.entries.add(self.i + 1) } as usize;

            let entry = Some(match unsafe { *entry } {
                0 => SratEntry::LegacyProcessorLocalAffinity(unsafe {
                    assert!(entry_len == size_of::<LegacyProcessorLocalAffinity>() + 2);
                    *(entry.add(2) as *const LegacyProcessorLocalAffinity)
                }),

                1 => SratEntry::MemoryAffinity(unsafe {
                    assert!(entry_len == size_of::<MemoryAffinity>() + 10);
                    *(entry.add(2) as *const MemoryAffinity)
                }),
                2 => SratEntry::ProcessorLocalAffinity(unsafe {
                    assert!(entry_len == size_of::<ProcessorLocalAffinity>() + 8);
                    *(entry.add(4) as *const ProcessorLocalAffinity)
                }),
                3 => SratEntry::GiccAffinity(unsafe {
                    assert!(entry_len == size_of::<GiccAffinity>() + 2);
                    *(entry.add(2) as *const GiccAffinity)
                }),
                // ignore GIC ITS Affinity and Generic Initiator Affinity
                _ => {
                    self.i += entry_len;
                    continue;
                }
            });
            self.i += entry_len;
            return entry;
        }
        None
    }
}

#[derive(Debug, Clone, Copy)]
#[expect(clippy::enum_variant_names)]
pub enum SratEntry {
    LegacyProcessorLocalAffinity(LegacyProcessorLocalAffinity),
    MemoryAffinity(MemoryAffinity),
    ProcessorLocalAffinity(ProcessorLocalAffinity),
    GiccAffinity(GiccAffinity),
    // unimplemented: Gic Its Affinity and Generic Initiator Affinity
    // our current focus is only on memory and cpus
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
/// For legacy xAPIC systems
pub struct LegacyProcessorLocalAffinity {
    proximity_domain_low: u8,
    apic_id: u8,
    flags: u32,
    sapic_id: u8,
    proximity_domain_high: [u8; 3],
    clock_domain: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct MemoryAffinity {
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
pub struct ProcessorLocalAffinity {
    proximity_domain: u32,
    x2apic_id: u32,
    flags: u32,
    clock_domain: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct GiccAffinity {
    proximity_domain: u32,
    processor_uid: u32,
    flags: u32,
    clock_domain: u32,
}

#[inline(always)]
pub(crate) fn to_usize(low: u32, high: u32) -> usize {
    #[cfg(target_pointer_width = "32")]
    return low as usize;

    #[cfg(target_pointer_width = "64")]
    {
        let mut low_and_high = [0u8; 8];
        low_and_high[0..=3].copy_from_slice(low.to_le_bytes().as_slice());
        low_and_high[4..=7].copy_from_slice(high.to_le_bytes().as_slice());
        usize::from_le_bytes(low_and_high)
    }
}
