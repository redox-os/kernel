use alloc::string::String;
use core::slice;

use crate::percpu;
use bitfield::Bit;
use rmm::{Arch, BumpAllocator, MemoryArea, PhysicalAddress};
use spin::once::Once;
use syscall::NumaMemoryPolicy;

pub const MAX_DOMAINS: usize = 128;
pub const MAX_MEM_REGIONS: usize = MAX_DOMAINS;

static DOMAIN_NODE_MAP: Once<&'static [Option<NumaNodeID>]> = Once::new();
static NUMA_CPUS: Once<&'static [Option<NumaNodeID>]> = Once::new();
static NUMA_MEMORY: Once<&'static [Option<NumaMemory>]> = Once::new();
static DISTANCES: Once<&'static [u8]> = Once::new();
static NUMA_NODES: Once<&'static [Option<NumaNode>]> = Once::new();

#[inline(always)]
pub fn is_supported() -> bool {
    if cfg!(target_arch = "x86_64") && cfg!(feature = "numa") {
        DOMAIN_NODE_MAP.get().is_some()
    } else {
        false
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy, Default)]
pub struct NumaNodeID(u32);

impl NumaNodeID {
    pub fn new(node_id: u32) -> Result<Self, String> {
        if node_id as usize >= MAX_DOMAINS {
            return Err(format!("Number of nodes supported is {}", MAX_DOMAINS));
        }
        Ok(NumaNodeID(node_id))
    }
    pub fn get(&self) -> u32 {
        self.0
    }
}

/// Each bit of this mask corresponds to an index of `FREE_LISTS`.
///
/// This abstraction allows future extensions to the number of memory regions supported.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FreeListMask {
    mask: u128,
}

impl FreeListMask {
    pub fn enable_index(&mut self, i: usize) {
        self.mask.set_bit(i, true);
    }

    #[allow(unused)]
    pub fn disable_index(&mut self, i: usize) {
        self.mask.set_bit(i, false);
    }

    pub fn is_enabled(&self, i: usize) -> bool {
        self.mask.bit(i)
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct NumaNode {
    pub cpus: u128,
    pub memories: FreeListMask,
}

#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct NumaMemory {
    pub start: usize,
    pub length: usize,
    pub node_id: NumaNodeID,
    #[cfg(target_pointer_width = "64")]
    _pad: [u8; 4],
    #[cfg(target_pointer_width = "32")]
    _pad: [u8; 12],
}

impl NumaMemory {
    pub fn new(start: usize, length: usize, node_id: NumaNodeID) -> Self {
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

pub fn init<A: Arch>(allocator: &mut BumpAllocator<A>) {
    #[cfg(target_arch = "x86_64")]
    {
        crate::acpi::srat::init(allocator, &DOMAIN_NODE_MAP, &NUMA_CPUS, &NUMA_MEMORY);
        crate::acpi::slit::init(&DISTANCES);
    }
}

pub type RegionMask = [bool; MAX_MEM_REGIONS];

pub fn init_arch(mask: &Option<RegionMask>) {
    if let Some(cpus) = NUMA_CPUS.get()
        && let Some(memories) = NUMA_MEMORY.get()
    {
        let numa_nodes = unsafe {
            let ptr = memories.as_ptr().add(MAX_DOMAINS).addr() as *mut Option<NumaNode>;
            slice::from_raw_parts_mut(ptr, MAX_DOMAINS)
        };
        numa_nodes.iter_mut().for_each(|e| *e = None);

        for (cpu_id, node_id) in cpus
            .iter()
            .enumerate()
            .filter_map(|(i, e)| Some((i, (*e)?)))
        {
            let node = &mut numa_nodes[node_id.get() as usize];
            if node.is_none() {
                *node = Some(NumaNode::default());
            }
            node.as_mut().unwrap().cpus |= 1u128 << cpu_id;
        }

        let mut index = 0;
        for (i, memory) in memories
            .iter()
            .enumerate()
            .filter_map(|(i, memory)| Some((i, memory.as_ref()?)))
        {
            if let Some(mask) = mask
                && !mask[i]
            {
                continue;
            }
            let node = &mut numa_nodes[memory.node_id.get() as usize];

            if node.is_none() {
                *node = Some(NumaNode::default());
            }

            node.as_mut().unwrap().memories.enable_index(index);
            index += 1;
        }

        for cpu in percpu::all_percpu_blocks() {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let cpu_id = cpu
                .misc_arch_info
                .apic_id_opt
                .get()
                .map(|e| e.get())
                .unwrap();

            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            let cpu_id = 0; // TODO

            let n = numa_nodes.iter().enumerate().find_map(|(i, node)| {
                let node = node.as_ref()?;
                if node.cpus & 1u128 << cpu_id != 0 {
                    Some((NumaNodeID::new(i as u32).unwrap(), node))
                } else {
                    None
                }
            });
            cpu.numa_node.set(n);
        }

        NUMA_NODES.call_once(|| numa_nodes);
    }
}

/// A helper function that prints information about NUMA - available nodes, cpus and memory blocks in them
/// their starts and lengths
pub fn dump_info() {
    if let Some(_) = DOMAIN_NODE_MAP.get()
        && let Some(cpus) = NUMA_CPUS.get()
        && let Some(memories) = NUMA_MEMORY.get()
        && let Some(nodes) = NUMA_NODES.get()
    {
        println!(
            "Number of NUMA nodes: {}",
            nodes.iter().filter(|e| e.is_some()).count()
        );
        for i in 0..cpus.len() {
            if let Some(cpu) = cpus[i] {
                println!("CPU {} : Node {}", i, cpu.get());
            }
        }
        for i in 0..memories.len() {
            if let Some(ref memory) = memories[i] {
                println!(
                    "Memory Block starting at address {:#x} of size {:#x} bytes : Node {}",
                    memory.start,
                    memory.length,
                    memory.node_id.get()
                );
            }
        }
    } else {
        println!("Unable to determine NUMA topology");
    }
}

pub struct NumaMemoryIter {
    i: usize,
    mem: &'static [Option<NumaMemory>],
}

impl Iterator for NumaMemoryIter {
    type Item = MemoryArea;

    fn next(&mut self) -> Option<Self::Item> {
        let mem = self.mem.get(self.i)?;
        self.i += 1;
        mem.as_ref().map(|e| MemoryArea {
            base: PhysicalAddress::new(e.start),
            size: e.length,
        })
    }
}

pub fn number_of_memory_regions() -> usize {
    if !cfg!(target_arch = "x86_64") || !cfg!(feature = "numa") {
        return 0;
    }

    if let Some(mem) = NUMA_MEMORY.get() {
        mem.iter().filter(|e| e.is_some()).count()
    } else {
        0 // TODO: or should 1 be returned?
    }
}

pub fn memory_regions() -> Option<NumaMemoryIter> {
    if !cfg!(feature = "numa") || !cfg!(target_arch = "x86_64") {
        return None;
    }
    NUMA_MEMORY.get().map(|mem| NumaMemoryIter { i: 0, mem })
}

pub fn nearest_next_memory_region(addr: usize, overlap: bool) -> Option<&'static NumaMemory> {
    NUMA_MEMORY
        .get()?
        .iter()
        .filter_map(|e| e.as_ref())
        .filter(|e| {
            if overlap {
                e.start >= addr
            } else {
                e.start > addr
            }
        })
        .min_by_key(|e| e.start)
}

pub fn current_node() -> Option<&'static NumaNode> {
    let cpu = percpu::PercpuBlock::current();
    Some(cpu.numa_node.get()?.1)
}

pub fn current_node_id() -> Option<NumaNodeID> {
    let cpu = percpu::PercpuBlock::current();
    Some(cpu.numa_node.get()?.0)
}

pub fn free_list_mask(mem_policy: NumaMemoryPolicy) -> Option<(FreeListMask, bool)> {
    match mem_policy {
        NumaMemoryPolicy::NodeLocalStrict => Some((current_node()?.memories, false)),
        NumaMemoryPolicy::NodeLocalLeniant => Some((current_node()?.memories, true)),
    }
}

pub struct FreeListMaskIter {
    i: usize,
    others: [u32; MAX_DOMAINS],
}

impl Iterator for FreeListMaskIter {
    type Item = FreeListMask;

    fn next(&mut self) -> Option<Self::Item> {
        let next_node_id = self.others.get(self.i)?;
        let next_node = &NUMA_NODES.get().unwrap()[*next_node_id as usize];
        self.i += 1;
        Some(next_node.as_ref()?.memories)
    }
}

pub fn free_lists_masks() -> Option<FreeListMaskIter> {
    let mut others: [(u32, u8); MAX_DOMAINS] = [(0u32, 0u8); MAX_DOMAINS];
    others.fill((u32::MAX, 0));
    let node_id = current_node_id()?;
    let mut iter = FreeListMaskIter {
        i: 0,
        others: [0u32; MAX_DOMAINS],
    };
    let distances = DISTANCES.get()?;
    let num_nodes = NUMA_NODES.get().unwrap().len();

    for (i, _node) in NUMA_NODES.get()?.iter().enumerate() {
        others[i] = (i as u32, distances[num_nodes * node_id.0 as usize + i]);
    }
    others.sort_by_key(|(_node_id, distance)| *distance);
    let others = others.map(|e| e.0);
    iter.others = others;

    Some(iter)
}
