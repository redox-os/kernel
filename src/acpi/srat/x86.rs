use core::iter;

use crate::{
    acpi::srat::{Srat, SratEntry},
    numa::{self, NUMA_NODES},
};

#[inline(always)]
fn to_usize(low: u32, high: u32) -> usize {
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

#[inline(always)]
fn to_single_int(high: &[u8; 3], low: u8) -> u32 {
    let mut high_and_low = [0u8; 4];
    high_and_low[0] = low;
    (high_and_low[1], high_and_low[2], high_and_low[3]) = (high[0], high[1], high[2]);
    u32::from_le_bytes(high_and_low)
}

pub fn init_srat(srat: &Srat) {
    for affinity in srat {
        match affinity {
            SratEntry::LegacyProcessorLocalAffinity(legacy_processor_local_affinity) => unsafe {
                numa::add_cpu(
                    legacy_processor_local_affinity.apic_id as u32,
                    to_single_int(
                        &legacy_processor_local_affinity.proximity_domain_high,
                        legacy_processor_local_affinity.proximity_domain_low,
                    ),
                )
            },
            SratEntry::MemoryAffinity(memory_affinity) => unsafe {
                if memory_affinity.length_low == 0 {
                    continue;
                }
                numa::add_memory(
                    memory_affinity.proximity_domain,
                    to_usize(
                        memory_affinity.base_address_low,
                        memory_affinity.base_address_high,
                    ),
                    to_usize(memory_affinity.length_low, memory_affinity.length_high),
                );
            },
            SratEntry::ProcessorLocalAffinity(processor_local_affinity) => unsafe {
                numa::add_cpu(
                    processor_local_affinity.x2apic_id,
                    processor_local_affinity.proximity_domain,
                )
            },
            _ => continue,
        }
    }
}
