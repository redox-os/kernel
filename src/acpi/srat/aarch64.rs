use core::{ops::Add, slice, u32};

use rmm::{Arch, BumpAllocator, FrameAllocator, FrameCount, PhysicalAddress};

use crate::{
    acpi::srat::{to_usize, Srat, SratEntry},
    cpu_set::MAX_CPU_COUNT,
    memory::{round_up_pages, PAGE_SIZE},
    numa::{self, assign_memory_id, assign_node_id, NumaMemory},
};

pub fn init_srat<A: Arch>(
    allocator: &mut BumpAllocator<A>,
    srat: &Srat,
) -> (&'static [u32], &'static [u32], &'static [NumaMemory]) {
    let dom_node_map_ptr = allocator
        .allocate(FrameCount::new(
            round_up_pages(numa::MAX_DOMAINS * size_of::<u32>()) / PAGE_SIZE,
        ))
        .expect("Failed to allocate pages for domain-node-map")
        .data();

    let va = crate::memory::RmmA::phys_to_virt(PhysicalAddress::new(dom_node_map_ptr)).data();
    let dom_node_map_ptr = va.data() as *mut u32;

    // occupies 521 bytes
    let dom_node_map = unsafe { slice::from_raw_parts_mut(dom_node_map_ptr, numa::MAX_DOMAINS) };

    // occupies 512 bytes
    let cpus = unsafe {
        slice::from_raw_parts_mut(
            dom_node_map_ptr.add(numa::MAX_DOMAINS as usize * size_of::<u32>()),
            MAX_CPU_COUNT as usize,
        )
    };

    // remaining 3072 bytes: can accomodate 128 Mem entries
    let mem = unsafe {
        slice::from_raw_parts_mut(
            dom_node_map_ptr
                .add(numa::MAX_DOMAINS)
                .add(MAX_CPU_COUNT as usize) as *mut NumaMemory,
            numa::MAX_DOMAINS * size_of::<NumaMemory>(),
        )
    };

    cpus.fill(u32::MAX);
    dom_node_map.fill(u32::MAX);
    mem.fill(NumaMemory {
        start: 0,
        length: 0,
        node_id: 0,
        _pad: [0; 4],
    });

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

    (dom_node_map, cpus, mem)
}
