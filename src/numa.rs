use core::{ops::Add, slice};

use crate::{
    acpi,
    cpu_set::{LogicalCpuId, MAX_CPU_COUNT},
    percpu,
    sync::{CleanLockToken, Mutex, L0},
};
use alloc::{sync::Arc, vec::Vec};
use hashbrown::HashMap;
use rmm::{Arch, BumpAllocator, MemoryArea, PhysicalAddress};
use spin::once::Once;
use syscall::{Error, Result, ENODATA, EOPNOTSUPP};

pub const MAX_DOMAINS: usize = 128;

static DOMAIN_NODE_MAP: Once<&'static [u32]> = Once::new();
static NUMA_CPUS: Once<&'static [u32]> = Once::new();
static NUMA_MEMORY: Once<&'static [NumaMemory]> = Once::new();
static DISTANCES: Once<&'static [u8]> = Once::new();
static NUMA_NODES: Once<&'static [NumaNode]> = Once::new();
pub static LOGICAL_CPU_ID_MAP: Once<Vec<u32>> = Once::new();

#[repr(C)]
#[derive(Debug, Clone)]
pub struct NumaNode {
    pub cpus: u128,
    pub memories: u128,
}

#[derive(Debug, Clone, Default)]
pub struct NumaMemory {
    pub start: usize,
    pub length: usize,
    pub node_id: u32,
    #[cfg(target_pointer_width = "64")]
    pub _pad: [u8; 4],
    #[cfg(target_pointer_width = "32")]
    pub _pad: [u8; 12],
}

impl NumaMemory {
    pub fn new(start: usize, length: usize, node_id: u32) -> Self {
        #[cfg(target_pointer_width = "64")]
        let _pad = [0u8; 4];

        #[cfg(target_pointer_width = "32")]
        let _pad = [0u8; 12];

        Self {
            start,
            length,
            node_id,
            _pad,
        }
    }
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

    if let Some(cpus) = NUMA_CPUS.get()
        && let Some(memories) = NUMA_MEMORY.get()
    {
        let numa_nodes = unsafe {
            slice::from_raw_parts_mut(
                memories.as_ptr().add(MAX_DOMAINS).addr() as *mut NumaNode,
                MAX_DOMAINS,
            )
        };
        numa_nodes.fill(NumaNode {
            cpus: 0,
            memories: 0,
        });

        for (i, cpu) in cpus.iter().enumerate().filter(|(i, e)| **e != u32::MAX) {
            numa_nodes[cpus[i] as usize].cpus |= 1u128 << i;
        }

        for (i, memory) in memories
            .iter()
            .enumerate()
            .filter(|(i, memory)| memory.length != 0)
        {
            numa_nodes[memory.node_id as usize].memories |= 1u128 << i;
        }

        NUMA_NODES.call_once(|| numa_nodes);
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

pub fn assign_memory_id() -> u8 {
    static mut MEMORY_ID: u8 = 0;
    if unsafe { MEMORY_ID } >= 128 {
        panic!("Maximum number of memory regions supported is 128");
    }
    let old = unsafe { MEMORY_ID };
    unsafe { MEMORY_ID = MEMORY_ID.add(1) };
    old
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
                memories[i].start, memories[i].length, memories[i].node_id
            );
        }
    } else {
        println!(
            "The system has either no support for NUMA or there was an error during initialisation"
        );
    }
}

pub struct NumaMemoryIter {
    i: usize,
    mem: &'static [NumaMemory],
}

impl Iterator for NumaMemoryIter {
    type Item = MemoryArea;

    fn next(&mut self) -> Option<Self::Item> {
        let mem = self.mem.get(self.i)?;
        if mem.length == 0 {
            return None;
        }
        self.i += 1;
        Some(MemoryArea {
            base: PhysicalAddress::new(mem.start),
            size: mem.length,
        })
    }
}

pub fn number_of_memory_regions() -> usize {
    if let Some(mem) = NUMA_MEMORY.get() {
        mem.iter()
            .map(|e| if e.length != 0 { 1 } else { 0 })
            .sum::<usize>()
    } else {
        0 // TODO: or should 1 be returned?
    }
}

pub fn memory_regions() -> Option<NumaMemoryIter> {
    if let Some(mem) = NUMA_MEMORY.get() {
        Some(NumaMemoryIter { i: 0, mem })
    } else {
        None
    }
}

pub fn nearest_next_memory_region(addr: usize, overlap: bool) -> Option<&'static NumaMemory> {
    NUMA_MEMORY
        .get()?
        .iter()
        .filter_map(|e| {
            if if overlap {
                e.start >= addr
            } else {
                e.start > addr
            } {
                Some(e)
            } else {
                None
            }
        })
        .min_by_key(|e| e.start)
}

pub fn nearest_preceding_memory_region(addr: usize, overlap: bool) -> Option<&'static NumaMemory> {
    NUMA_MEMORY
        .get()?
        .iter()
        .filter_map(|e| {
            if if overlap {
                e.start <= addr
            } else {
                e.start < addr
            } {
                Some(e)
            } else {
                None
            }
        })
        .max_by_key(|e| e.start)
}

pub fn get_numa_info(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let cpu_info = NUMA_CPUS
        .get()
        .ok_or(Error::new(EOPNOTSUPP))?
        .iter()
        .map(|e| e.to_ne_bytes())
        .flatten()
        .collect::<Vec<u8>>();
    let mem_info = NUMA_MEMORY
        .get()
        .ok_or(Error::new(EOPNOTSUPP))?
        .iter()
        .map(|e| {
            [
                e.start.to_ne_bytes(),
                e.length.to_ne_bytes(),
                (e.node_id as usize).to_ne_bytes(),
            ]
        })
        .flatten()
        .flatten()
        .collect::<Vec<u8>>();
    let mut numa_info = Vec::new();
    numa_info.extend(cpu_info);
    numa_info.extend(mem_info);
    Ok(numa_info)
}

pub fn get_numa_distance_info(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    Ok(DISTANCES
        .get()
        .ok_or(Error::new(ENODATA))?
        .iter()
        .map(|e| *e)
        .collect())
}

pub fn get_numa_dom_info(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    Ok(DOMAIN_NODE_MAP
        .get()
        .ok_or(Error::new(EOPNOTSUPP))?
        .iter()
        .map(|e| e.to_ne_bytes())
        .flatten()
        .collect())
}

pub fn free_list_mask() -> Option<u128> {
    let cpu = percpu::PercpuBlock::current();
    let cpu_id = if let Some(map) = LOGICAL_CPU_ID_MAP.get() {
        *map.get(cpu.cpu_id.get() as usize).unwrap()
    } else {
        cpu.cpu_id.get()
    };

    let mut mask = 0;
    if let Some(nodes) = NUMA_NODES.get() {
        let node = nodes.iter().find_map(|node| {
            if node.cpus & 1u128 << cpu_id != 0 {
                Some(node)
            } else {
                None
            }
        })?;
        return Some(node.memories);
    }

    None
}
