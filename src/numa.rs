use crate::{
    acpi,
    cpu_set::LogicalCpuId,
    sync::{CleanLockToken, Mutex, L0},
};
use alloc::{sync::Arc, vec::Vec};
use hashbrown::HashMap;
use rmm::{Arch, BumpAllocator};
use spin::once::Once;

pub const MAX_DOMAINS: usize = 128;

static DOMAIN_NODE_MAP: Once<&'static [u32]> = Once::new();
static NUMA_CPUS: Once<&'static [u32]> = Once::new();
static NUMA_MEMORY: Once<&'static [NumaMemory]> = Once::new();
static DISTANCES: Once<&'static [u8]> = Once::new();

#[derive(Debug, Clone)]
pub struct NumaMemory {
    pub start: usize,
    pub length: usize,
    pub dom: u32,
    pub _pad: [u8; 4],
}

#[derive(Debug)]
pub struct NumaCpu {
    pub id: u32,
}

pub fn init<A: Arch>(allocator: &mut BumpAllocator<A>) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    {
        acpi::srat::init(allocator, &DOMAIN_NODE_MAP, &NUMA_CPUS, &NUMA_MEMORY);
        acpi::slit::init(allocator, &DISTANCES);
    }
}

pub fn assign_node_id(modify: bool) -> u8 {
    static mut NODE_ID: u8 = 0;
    if unsafe { NODE_ID } >= 128 {
        panic!("Maximum number of domains supported is 128");
    }
    unsafe {
        NODE_ID += 1;
        let return_value = NODE_ID - 1;
        if !modify {
            NODE_ID -= 1;
        }
        return_value
    }
}

pub fn domain_to_node_id(domain_id: u32) -> Option<u32> {
    Some(*DOMAIN_NODE_MAP.get()?.get(domain_id as usize)?)
}

pub fn cpu_belongs_to_which_node(cpu_id: usize) -> Option<u32> {
    Some(*NUMA_CPUS.get()?.get(cpu_id)?)
}

/// A helper function that prints information about NUMA - available nodes, cpus and memory blocks in them
/// their starts and lengths
pub fn dump_info() {
    if let Some(map) = DOMAIN_NODE_MAP.get()
        && let Some(cpus) = NUMA_CPUS.get()
        && let Some(memories) = NUMA_MEMORY.get()
    {
        println!(
            "Number of proximity domains: {}",
            map.iter()
                .map(|e| if *e != u32::MAX { 1 } else { 0 })
                .sum::<u32>()
        );
        println!("Number of NUMA nodes: {}", assign_node_id(false));
        for i in 0..cpus.len() {
            if cpus[i] == u32::MAX {
                continue;
            }
            println!("CPU {} : Node {}", i, cpus[i])
        }
        for i in 0..memories.len() {
            if memories[i].length == 0 {
                continue;
            }
            println!(
                "Memory Block starting at address {:#x} of size {:#x} bytes : Node {}",
                memories[i].start, memories[i].length, memories[i].dom
            );
        }
    } else {
        println!(
            "The system has either no support for NUMA or there was an error during initialisation"
        );
    }
}
