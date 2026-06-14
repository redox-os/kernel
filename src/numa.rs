#[cfg(all(
    feature = "acpi",
    any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::acpi;
use crate::{
    cpu_set::LogicalCpuId,
    sync::{CleanLockToken, Mutex, L0},
};
use alloc::{sync::Arc, vec::Vec};
use hashbrown::HashMap;
use spin::once::Once;

pub static NUMA_NODES: Once<HashMap<u32, NumaNode>> = Once::new();
pub static NUMBER_OF_DOMAINS: Once<u32> = Once::new();

#[derive(Debug)]
pub struct NumaMemory {
    pub start: usize,
    pub length: usize,
}

#[derive(Debug)]
pub struct NumaCpu {
    pub id: u32,
}

#[derive(Default, Debug)]
/// Represents a single NUMA logical node. A node is different from a domain. NUMA domain
/// refers to what exists physically. A NUMA node on the other hand is a logical one, with domains having
/// only CPUs or memory grouped together with other CPUs or memories.
///
/// See the function `reorganise` below.
pub struct NumaNode {
    cpus: Vec<NumaCpu>,
    memory: Vec<NumaMemory>,
    distances: Vec<(u32, u8)>,
}

pub fn init() {
    NUMA_NODES.call_once(|| HashMap::new());

    #[cfg(all(
        feature = "acpi",
        any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        acpi::srat::init();
        acpi::slit::init();
        return;
    }

    #[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
    {
        todo!()
    }

    unsafe {
        sort_by_distances();
        reorganise();
        shrink();
    }

    // From this point onwards, the global static `NUMA_NODES` or any of its elements
    // MUST NOT be mutated by the usual unsafe magic that functions in this file use.
}

pub unsafe fn add_cpu(id: u32, node_id: u32) {
    let numa_nodes = NUMA_NODES.get().unwrap();

    /* 💀💀💀 HIGHLY UNSAFE 💀💀💀 */
    let numa_nodes = unsafe { &mut *(&raw const *numa_nodes as *mut HashMap<u32, NumaNode>) };

    if let Some(node) = numa_nodes.get_mut(&id) {
        node.cpus.push(NumaCpu { id });
    } else {
        let mut cpus = Vec::new();
        cpus.push(NumaCpu { id });
        numa_nodes.insert(
            node_id,
            NumaNode {
                cpus,
                memory: Vec::new(),
                distances: Vec::new(),
            },
        );
    }
}

pub unsafe fn add_memory(node_id: u32, start: usize, length: usize) {
    let numa_nodes = NUMA_NODES.get().unwrap();

    /* 💀💀💀 HIGHLY UNSAFE 💀💀💀 */
    let numa_nodes = unsafe { &mut *(&raw const *numa_nodes as *mut HashMap<u32, NumaNode>) };

    if let Some(node) = numa_nodes.get_mut(&node_id) {
        node.memory.push(NumaMemory { start, length });
    } else {
        let mut memory = Vec::new();
        memory.push(NumaMemory { start, length });
        numa_nodes.insert(
            node_id,
            NumaNode {
                cpus: Vec::new(),
                memory,
                distances: Vec::new(),
            },
        );
    }
}

pub unsafe fn set_distance(src: u32, target: u32, distance: u8) {
    /* 💀💀💀 HIGHLY UNSAFE 💀💀💀 */
    let nodes =
        unsafe { &mut *(&raw const *(NUMA_NODES.get().unwrap()) as *mut HashMap<u32, NumaNode>) };

    let src = nodes.get_mut(&src).unwrap();
    src.distances.push((target, distance));
}

unsafe fn shrink() {
    /* 💀💀💀 HIGHLY UNSAFE 💀💀💀 */
    let nodes =
        unsafe { &mut *(&raw const *(NUMA_NODES.get().unwrap()) as *mut HashMap<u32, NumaNode>) };

    nodes.shrink_to_fit();

    for (id, node) in nodes {
        node.cpus.shrink_to_fit();
        node.distances.shrink_to_fit();
        node.memory.shrink_to_fit();
    }
}

/// Reorganises CPUs and memories into nodes. If a NUMA domain has only a CPU but no memory, it is
/// put into a node with a memory that is nearest to it. Similarly, if a NUMA domain has only memory but no
/// CPUs, the memory is put into a node that has a CPU that is nearest to it.
///
/// See the comment above the definition of `NumaNode`.
unsafe fn reorganise() {
    /* 💀💀💀 HIGHLY UNSAFE 💀💀💀 */
    let nodes =
        unsafe { &mut *(&raw const *(NUMA_NODES.get().unwrap()) as *mut HashMap<u32, NumaNode>) };
    let ids = nodes.keys().map(|e| *e).collect::<Vec<u32>>();

    for id in ids {
        let node = nodes.remove(&id).unwrap();

        if node.cpus.len() == 0 {
            put_for_adoption(nodes, node.distances, Some(node.memory), None);
        } else {
            nodes.insert(id, node);
        }
    }
}

fn put_for_adoption(
    nodes: &mut HashMap<u32, NumaNode>,
    distances: Vec<(u32, u8)>,
    memories: Option<Vec<NumaMemory>>,
    cpus: Option<Vec<NumaCpu>>,
) {
    if let Some(memories) = memories {
        assert!(cpus.is_none());
        let (nearest_node_id, _) = distances.first().unwrap();
        let nearest_node = nodes.get_mut(nearest_node_id).unwrap();
        nearest_node.memory.extend(memories);
    } else if let Some(cpus) = cpus {
        assert!(memories.is_none());
        let (nearest_node_id, _) = distances.first().unwrap();
        let nearest_node = nodes.get_mut(nearest_node_id).unwrap();
        nearest_node.cpus.extend(cpus);
    }
}

unsafe fn sort_by_distances() {
    /* 💀💀💀 HIGHLY UNSAFE 💀💀💀 */
    let nodes =
        unsafe { &mut *(&raw const *(NUMA_NODES.get().unwrap()) as *mut HashMap<u32, NumaNode>) };

    for (id, node) in nodes {
        node.distances.sort_by_key(|(_, e)| *e);
    }
}
