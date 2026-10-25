use crate::{
    acpi::srat::{to_usize, Srat, SratEntry},
    cpu_set,
    numa::{self, NumaMemory, NumaNodeID},
};

#[inline(always)]
fn to_single_int(high: &[u8; 3], low: u8) -> u32 {
    let mut high_and_low = [0u8; 4];
    high_and_low[0] = low;
    (high_and_low[1], high_and_low[2], high_and_low[3]) = (high[0], high[1], high[2]);
    u32::from_le_bytes(high_and_low)
}

pub fn init_srat(
    dom_node_map: &mut [Option<NumaNodeID>],
    cpus: &mut [Option<NumaNodeID>],
    memories: &mut [Option<NumaMemory>],
    srat: &Srat,
) {
    let mut cpu_count = 0;
    let mut memory_count = 0;

    srat.into_iter().for_each(|e| match e {
        SratEntry::LegacyProcessorLocalAffinity(legacy_processor_local_affinity) => {
            if legacy_processor_local_affinity.flags & 1 != 0 {
                cpu_count += 1
            }
        }
        SratEntry::MemoryAffinity(memory_affinity) => {
            if memory_affinity.flags & 1 != 0 && memory_affinity.flags & (1 << 1) == 0 {
                memory_count += 1
            }
        }

        SratEntry::ProcessorLocalAffinity(processor_local_affinity)
            if processor_local_affinity.flags & 1 != 0 =>
        {
            cpu_count += 1
        }
        _ => (),
    });

    assert!(
        memory_count <= numa::MAX_MEM_REGIONS,
        "Found {} memory blocks while only a maximum of {} are supported",
        memory_count,
        numa::MAX_DOMAINS
    );

    assert!(
        cpu_count <= cpu_set::MAX_CPU_COUNT,
        "Found more number of CPUs than supported"
    );

    let mut node_id = 0u32;
    let mut memory_id = 0u32;

    for affinity in srat {
        match affinity {
            SratEntry::LegacyProcessorLocalAffinity(legacy_processor_local_affinity) => {
                if legacy_processor_local_affinity.flags & 1 == 0 {
                    // processor disabled
                    continue;
                }
                let dom = to_single_int(
                    &legacy_processor_local_affinity.proximity_domain_high,
                    legacy_processor_local_affinity.proximity_domain_low,
                );
                if dom_node_map[dom as usize].is_none() {
                    dom_node_map[dom as usize] = Some(NumaNodeID::new(node_id).unwrap());
                    node_id += 1;
                }
                cpus[legacy_processor_local_affinity.apic_id as usize] = dom_node_map[dom as usize];
            }
            SratEntry::MemoryAffinity(memory_affinity) => {
                if memory_affinity.flags & 1 == 0 {
                    // memory is not enabled
                    continue;
                }
                if memory_affinity.flags & (1 << 1) != 0 {
                    // memory is hot-pluggable
                    continue;
                }
                let dom = memory_affinity.proximity_domain;
                let start = to_usize(
                    memory_affinity.base_address_low,
                    memory_affinity.base_address_high,
                );
                let length = to_usize(memory_affinity.length_low, memory_affinity.length_high);
                if dom_node_map[dom as usize].is_none() {
                    dom_node_map[dom as usize] = Some(NumaNodeID::new(node_id).unwrap());
                    node_id += 1;
                }
                memories[memory_id as usize] = Some(numa::NumaMemory::new(
                    start,
                    length,
                    dom_node_map[dom as usize].unwrap(),
                ));
                memory_id += 1;
            }
            SratEntry::ProcessorLocalAffinity(processor_local_affinity) => {
                if processor_local_affinity.flags & 1 == 0 {
                    // processor disabled
                    continue;
                }
                let dom = processor_local_affinity.proximity_domain;
                if dom_node_map[dom as usize].is_none() {
                    dom_node_map[dom as usize] = Some(NumaNodeID::new(node_id).unwrap());
                    node_id += 1;
                }
                cpus[processor_local_affinity.x2apic_id as usize] = dom_node_map[dom as usize];
            }
            _ => continue,
        }
    }
}
