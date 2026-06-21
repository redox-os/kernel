use core::iter;

use hashbrown::HashMap;

use crate::{
    acpi::srat::{to_usize, Srat, SratEntry},
    numa::{self, NumaNode, NUMA_NODES},
};

#[inline(always)]
fn to_single_int(high: &[u8; 3], low: u8) -> u32 {
    let mut high_and_low = [0u8; 4];
    high_and_low[0] = low;
    (high_and_low[1], high_and_low[2], high_and_low[3]) = (high[0], high[1], high[2]);
    u32::from_le_bytes(high_and_low)
}

pub fn init_srat(numa_nodes: &mut HashMap<u32, NumaNode>, srat: &Srat) {
    for affinity in srat {
        match affinity {
            SratEntry::LegacyProcessorLocalAffinity(legacy_processor_local_affinity) => {
                numa::add_cpu(
                    numa_nodes,
                    legacy_processor_local_affinity.apic_id as u32,
                    to_single_int(
                        &legacy_processor_local_affinity.proximity_domain_high,
                        legacy_processor_local_affinity.proximity_domain_low,
                    ),
                )
            }
            SratEntry::MemoryAffinity(memory_affinity) => {
                if memory_affinity.length_low == 0 {
                    continue;
                }
                numa::add_memory(
                    numa_nodes,
                    memory_affinity.proximity_domain,
                    to_usize(
                        memory_affinity.base_address_low,
                        memory_affinity.base_address_high,
                    ),
                    to_usize(memory_affinity.length_low, memory_affinity.length_high),
                );
            }
            SratEntry::ProcessorLocalAffinity(processor_local_affinity) => numa::add_cpu(
                numa_nodes,
                processor_local_affinity.x2apic_id,
                processor_local_affinity.proximity_domain,
            ),
            _ => continue,
        }
    }
}
