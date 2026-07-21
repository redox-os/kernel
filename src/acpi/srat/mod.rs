//! See <https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#system-resource-affinity-table-srat>

use core::slice;

use hashbrown::HashMap;
use rmm::{Arch, BumpAllocator, FrameAllocator};
use spin::once::Once;

use crate::{
    acpi::{find_sdt, get_sdt_signature, rxsdt::Rxsdt, sdt::Sdt, srat, RXSDT_ENUM},
    cpu_set::MAX_CPU_COUNT,
    find_one_sdt, memory,
    numa::{self, NumaMemory},
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
    entries: *const u8,
}

pub fn init<A: Arch>(
    allocator: &mut BumpAllocator<A>,
    map: &Once<&'static [u32]>,
    once_cpus: &Once<&'static [u32]>,
    mem: &Once<&'static [NumaMemory]>,
) {
    let dom_node_map = allocator
        .allocate(rmm::FrameCount::new(1))
        .expect("Failed to allocate memory for storing NUMA info");

    let dom_node_map_ptr =
        unsafe { crate::memory::RmmA::phys_to_virt(dom_node_map).data() as *mut u32 };

    // Occupies 512 bytes (1/8th of a page)
    let dom_node_map: &'static mut [u32] =
        unsafe { slice::from_raw_parts_mut(dom_node_map_ptr, numa::MAX_DOMAINS) };

    // occupies 512 bytes (1/8th of a page)
    let cpus: &'static mut [u32] = unsafe {
        slice::from_raw_parts_mut(
            dom_node_map_ptr.add(numa::MAX_DOMAINS) as *mut u32,
            MAX_CPU_COUNT as usize,
        )
    };

    // total occupied till now: 1024 bytes, remaining 3072 bytes, can accomodate 128 memory entries
    let memories: &'static mut [NumaMemory] = unsafe {
        slice::from_raw_parts_mut(
            cpus.as_ptr().add(numa::MAX_DOMAINS) as *mut NumaMemory,
            numa::MAX_DOMAINS,
        )
    };

    dom_node_map.fill(u32::MAX);
    cpus.fill(u32::MAX);
    memories.fill(NumaMemory::default());

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
            entries: (sdt.data_address() + 12) as *const u8,
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
            let entry = unsafe { self.srat.entries.add(self.i as usize) };
            let entry_len = unsafe { *self.srat.entries.add(self.i as usize + 1) };

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
                // ignore GIC ITS Affinity and Generic Initiator Affinity
                _ => {
                    self.i += entry_len as u32;
                    continue;
                }
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
    // unimplemented: Gic Its Affinity and Generic Initiator Affinity
    // our current focus is only on memory and cpus
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
