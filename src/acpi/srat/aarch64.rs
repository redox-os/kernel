use core::{ops::Add, slice, u32};

use rmm::{Arch, BumpAllocator, FrameAllocator, FrameCount, PhysicalAddress};

use crate::{
    acpi::srat::{to_usize, Srat, SratEntry},
    cpu_set::MAX_CPU_COUNT,
    memory::{round_up_pages, PAGE_SIZE},
    numa::{self, assign_memory_id, assign_node_id, NumaMemory},
};

pub fn init_srat(dom_node_map: &mut [u32], cpus: &mut [u32], mem: &mut [NumaMemory], srat: &Srat) {
    let mut cpu_count = 0;
    let mut memory_count = 0;

    srat.into_iter().for_each(|e| match e {
        SratEntry::GiccAffinity(gicc_affinity) => {
            if gicc_affinity.flags & 1 != 0 {
                cpu_count += 1
            }
        }
        SratEntry::MemoryAffinity(memory_affinity) => {
            if memory_affinity.flags & 1 != 0 && memory_affinity.flags & (1 << 1) == 0 {
                memory_count += 1
            }
        }
        _ => (),
    });

    assert!(
        memory_count <= numa::MAX_DOMAINS,
        "Found {} memory blocks while only a maximum of {} are supported",
        memory_count,
        numa::MAX_DOMAINS
    );

    assert!(
        cpu_count <= MAX_CPU_COUNT,
        "Found more number of CPUs than supported"
    );

    for affinity in srat {
        match affinity {
            SratEntry::MemoryAffinity(memory_affinity) => {
                let start = to_usize(
                    memory_affinity.base_address_low,
                    memory_affinity.base_address_high,
                );
                let length = to_usize(memory_affinity.length_low, memory_affinity.length_high);
                if length == 0 {
                    continue;
                }
                if memory_affinity.flags & 1 == 0 {
                    // memory disabled
                    continue;
                }
                if memory_affinity.flags & (1 << 1) != 0 {
                    // memory hot-pluggable
                    continue;
                }
                if dom_node_map[memory_affinity.proximity_domain as usize] == u32::MAX {
                    let node = assign_node_id(true);
                    dom_node_map[memory_affinity.proximity_domain as usize] = node as u32;
                }
                let mem_id = assign_memory_id() as u32;
                mem[mem_id as usize] = NumaMemory {
                    start,
                    length,
                    node_id: dom_node_map[memory_affinity.proximity_domain as usize],
                    _pad: [0u8; 4],
                };
            }
            SratEntry::GiccAffinity(gicc_affinity) => {
                if gicc_affinity.flags & 1 == 0 {
                    // disabled
                    continue;
                }
                let id = gicc_affinity.processor_uid;
                let dom = gicc_affinity.proximity_domain;
                if dom_node_map[dom as usize] == u32::MAX {
                    let node = assign_node_id(true);
                    dom_node_map[dom as usize] = node as u32;
                }
                cpus[id as usize] = dom_node_map[dom as usize];
            }
            _ => continue,
        }
    }
}
