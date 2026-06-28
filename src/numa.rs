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

#[derive(Debug)]
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
    }
}

// pub fn set_distance(nodes: &mut HashMap<u32, NumaNode>, src: u32, target: u32, distance: u8) {
//     let src = nodes.get_mut(&src).unwrap();
//     src.distances.push((target, distance));
// }

// fn shrink(nodes: &mut HashMap<u32, NumaNode>) {
//     nodes.shrink_to_fit();

//     for (id, node) in nodes {
//         node.cpus.shrink_to_fit();
//         node.distances.shrink_to_fit();
//         node.memory.shrink_to_fit();
//     }
// }

// /// Reorganises CPUs and memories into nodes. If a NUMA domain has only a CPU but no memory, it is
// /// put into a node with a memory that is nearest to it. Similarly, if a NUMA domain has only memory but no
// /// CPUs, the memory is put into a node that has a CPU that is nearest to it.
// ///
// /// See the comment above the definition of `NumaNode`.
// fn reorganise(nodes: &mut HashMap<u32, NumaNode>) {
//     let ids = nodes.keys().map(|e| *e).collect::<Vec<u32>>();

//     for id in ids {
//         let node = nodes.remove(&id).unwrap();

//         if node.cpus.len() == 0 {
//             assert!(node.memory.len() != 0);
//             put_for_adoption(nodes, node.distances, Some(node.memory), None, id);
//         } else if node.memory.len() == 0 {
//             put_for_adoption(nodes, node.distances, None, Some(node.cpus), id);
//         } else {
//             nodes.insert(id, node);
//         }
//     }
// }

// fn put_for_adoption(
//     nodes: &mut HashMap<u32, NumaNode>,
//     distances: Vec<(u32, u8)>,
//     memories: Option<Vec<NumaMemory>>,
//     cpus: Option<Vec<NumaCpu>>,
//     orphan_node_id: u32, // id of the node containing only memory / CPU (orphan)
// ) {
//     if let Some(memories) = memories {
//         assert!(cpus.is_none());
//         let foster_node = if !distances.is_empty() {
//             let (nearest_node_id, distance) = distances.first().unwrap();
//             nodes.get_mut(nearest_node_id).unwrap()
//         } else {
//             let foster_node_id = {
//                 let mut node_ids = nodes.keys();
//                 let foster_node = node_ids
//                     .find(|node_id| **node_id != orphan_node_id)
//                     .unwrap();
//                 *foster_node
//             };
//             nodes.get_mut(&foster_node_id).unwrap() // panic not possible since there must be atleast one other domain with a cpu
//         };
//         foster_node.memory.extend(memories);
//     } else if let Some(cpus) = cpus {
//         assert!(memories.is_none());
//         let foster_node = if !distances.is_empty() {
//             let (nearest_node_id, distance) = distances.first().unwrap();
//             nodes.get_mut(nearest_node_id).unwrap()
//         } else {
//             let foster_node_id = {
//                 let mut node_ids = nodes.keys();
//                 let foster_node = node_ids
//                     .find(|node_id| **node_id != orphan_node_id)
//                     .unwrap();
//                 *foster_node
//             };
//             nodes.get_mut(&foster_node_id).unwrap() // panic not possible since there must be atleast one other domain with memory
//         };
//         foster_node.cpus.extend(cpus);
//     } else {
//         unreachable!() // this should never happen
//     };

//     for (_, node) in nodes {
//         if let Some(idx) = node.distances.iter().position(|e| e.0 == orphan_node_id) {
//             let _ = node.distances.remove(idx);
//         }
//     }
// }

// fn sort_by_distances(nodes: &mut HashMap<u32, NumaNode>) {
//     for (id, node) in nodes {
//         node.distances.sort_by_key(|(_, e)| *e);
//     }
// }

pub fn assign_node_id() -> u8 {
    static NODE_ID: u8 = 0;
    NODE_ID.checked_add(1).unwrap();
    NODE_ID - 1
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
        println!(
            "Number of NUMA nodes: {}",
            memories
                .iter()
                .map(|m| m.dom)
                .max()
                .map_or(0, |e| e)
                .max(cpus.iter().max().map_or(0, |e| *e))
        );
        for i in 0..cpus.len() {
            println!("CPU {} : Node {}", i, cpus[i])
        }
        for i in 0..memories.len() {
            println!(
                "Memory Block starting at address {:#x} of size {} : Node {}",
                memories[i].start, memories[i].length, memories[i].dom
            );
        }
    } else {
        println!(
            "The system has either no support for NUMA or there was an error during initialisation"
        );
    }
}
