use crate::{
    cpu_set::LogicalCpuId,
    sync::{Mutex, L0},
};
use alloc::{sync::Arc, vec::Vec};

pub static NUMA_NODES: Mutex<L0, Vec<Arc<NumaNode>>> = Mutex::new(Vec::new());

pub struct NumaMemory;

pub struct NumaNode {
    cpus: Vec<LogicalCpuId>,
    memory: Vec<NumaMemory>,
}
