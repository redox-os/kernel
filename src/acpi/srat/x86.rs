use core::{iter, slice};

use hashbrown::HashMap;
use rmm::{Arch, BumpAllocator, FrameAllocator};

use crate::{
    acpi::srat::{to_usize, Srat, SratEntry},
    cpu_set,
    memory::{self, PAGE_SIZE},
    numa::{self, NumaMemory},
};

#[inline(always)]
fn to_single_int(high: &[u8; 3], low: u8) -> u32 {
    let mut high_and_low = [0u8; 4];
    high_and_low[0] = low;
    (high_and_low[1], high_and_low[2], high_and_low[3]) = (high[0], high[1], high[2]);
    u32::from_le_bytes(high_and_low)
}

pub fn init_srat<A: Arch>(
    allocator: &mut BumpAllocator<A>,
    srat: &Srat,
) -> (&'static [u32], &'static [u32], &'static [NumaMemory]) {
    let dom_node_map = allocator
        .allocate(rmm::FrameCount::new(
            memory::round_up_pages(numa::MAX_DOMAINS * size_of::<u32>()) / PAGE_SIZE,
        ))
        .expect("Failed to allocate memory for storing NUMA info");
    let mut mapper = unsafe { rmm::PageMapper::current(rmm::TableKind::Kernel, allocator) };
    let mut flags = rmm::PageFlags::<A>::new();
    let flags = flags.write(true);
    let dom_node_map_ptr = unsafe {
        let (va, flush) = mapper
            .map_linearly(dom_node_map, flags)
            .expect("Failed to map NUMA info pages");
        flush.flush();
        va.data() as *mut u32
    };
    // Occupies 512 bytes (1/8th of a page)
    let dom_node_map: &'static mut [u32] =
        unsafe { slice::from_raw_parts_mut(dom_node_map_ptr, numa::MAX_DOMAINS) };
    dom_node_map.fill(u32::MAX);

    let mut cpu_count = 0;
    let mut memory_count = 0;

    srat.into_iter().for_each(|e| match e {
        SratEntry::LegacyProcessorLocalAffinity(legacy_processor_local_affinity) => cpu_count += 1,
        SratEntry::MemoryAffinity(memory_affinity) => memory_count += 1,
        SratEntry::ProcessorLocalAffinity(processor_local_affinity) => todo!(),
        _ => (),
    });

    assert!(
        memory_count <= numa::MAX_DOMAINS,
        "Found {} memory blocks while only a maximum of {} are supported",
        memory_count,
        numa::MAX_DOMAINS
    );

    assert!(
        cpu_count <= cpu_set::MAX_CPU_COUNT,
        "Found more number of CPUs than supported"
    );

    // occupies 512 bytes (1/8th of a page)
    let cpus: &'static mut [u32] = unsafe {
        slice::from_raw_parts_mut(
            dom_node_map_ptr.add(numa::MAX_DOMAINS) as *mut u32,
            numa::MAX_DOMAINS,
        )
    };

    cpus.fill(u32::MAX);

    // total occupied till now: 1024 bytes, remaining 3072 bytes, can accomodate 128 memory entries

    let memories: &'static mut [NumaMemory] = unsafe {
        slice::from_raw_parts_mut(
            cpus.as_ptr().add(numa::MAX_DOMAINS) as *mut NumaMemory,
            numa::MAX_DOMAINS,
        )
    };

    memories.fill(NumaMemory {
        start: 0,
        length: 0,
        dom: 0,
        _pad: [0; 4],
    });

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
                if dom_node_map[dom as usize] == u32::MAX {
                    let node_id = numa::assign_node_id(true);
                    dom_node_map[dom as usize] = node_id as u32;
                }
                cpus[legacy_processor_local_affinity.apic_id as usize] = dom_node_map[dom as usize];
            }
            SratEntry::MemoryAffinity(memory_affinity) => {
                if memory_affinity.flags & 1 == 0 {
                    // memory is not enabled
                    continue;
                }
                let dom = memory_affinity.proximity_domain;
                if memory_affinity.length_low == 0 {
                    continue;
                }
                let start = to_usize(
                    memory_affinity.base_address_low,
                    memory_affinity.base_address_high,
                );
                let length = to_usize(memory_affinity.length_low, memory_affinity.length_high);
                if dom_node_map[dom as usize] == u32::MAX {
                    let node_id = numa::assign_node_id(true);
                    dom_node_map[dom as usize] = node_id as u32;
                }
                memories[dom_node_map[dom as usize] as usize] = numa::NumaMemory {
                    start,
                    length,
                    dom: dom_node_map[dom as usize],
                    _pad: [0u8; 4],
                };
            }
            SratEntry::ProcessorLocalAffinity(processor_local_affinity) => {
                if processor_local_affinity.flags & 1 == 0 {
                    // processor disabled
                    continue;
                }
                let dom = processor_local_affinity.proximity_domain;
                if dom_node_map[dom as usize] == u32::MAX {
                    let node_id = numa::assign_node_id(true);
                    dom_node_map[dom as usize] = node_id as u32;
                }
                cpus[dom_node_map[dom as usize] as usize] =
                    processor_local_affinity.proximity_domain;
            }
            _ => continue,
        }
    }
    let mut flags = rmm::PageFlags::<A>::new();
    let flags = flags.write(false);
    let flush = unsafe {
        mapper
            .remap(rmm::VirtualAddress::new(dom_node_map_ptr.addr()), flags)
            .expect("Unable to make NUMA info page read-only")
    };
    flush.flush();
    (dom_node_map, cpus, memories)
}
