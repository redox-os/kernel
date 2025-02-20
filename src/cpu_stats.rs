use core::{
    fmt::Display,
    sync::atomic::{AtomicU64, Ordering},
};

use alloc::vec::Vec;
use hashbrown::HashMap;
use log::warn;
use spin::{Lazy, Mutex};

use crate::cpu_set::LogicalCpuId;

static CPU_STATS: Lazy<Mutex<HashMap<LogicalCpuId, CpuStats>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CONTEXT_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);
static IRQ_COUNT: Lazy<Mutex<[u64; 255]>> = Lazy::new(|| Mutex::new([0; 255]));

#[derive(Copy, Clone, Debug)]
pub enum CpuState {
    Idle,
    Kernel,
    User,
}

#[derive(Clone, Copy, Debug)]
pub struct CpuStats {
    pub id: LogicalCpuId,
    pub user: usize,
    pub nice: usize,
    pub kernel: usize,
    pub idle: usize,
    pub irq: usize,
    state: CpuState,
}

impl CpuStats {
    fn new(cpu_id: LogicalCpuId) -> Self {
        Self {
            id: cpu_id,
            user: 0,
            nice: 0,
            kernel: 0,
            idle: 0,
            irq: 0,
            state: CpuState::Idle,
        }
    }
}

pub fn add_cpu(cpu_id: LogicalCpuId) {
    CPU_STATS.lock().insert(cpu_id, CpuStats::new(cpu_id));
}

pub fn add_context_switch() {
    CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::SeqCst);
}

pub fn get_context_switch_count() -> u64 {
    CONTEXT_SWITCH_COUNT.load(Ordering::SeqCst)
}

pub fn get_all() -> Vec<CpuStats> {
    let mut res: Vec<_> = CPU_STATS.lock().values().cloned().collect();
    res.sort_unstable_by_key(|stat| stat.id.get());

    res
}

pub fn set_state(cpu_id: LogicalCpuId, state: CpuState) {
    let mut lock = CPU_STATS.lock();
    let Some(stats) = lock.get_mut(&cpu_id) else {
        warn!("could not set cpu state for cpu {cpu_id}: cpu is not registered");
        return;
    };
    stats.state = state;
}

pub fn add_time(cpu_id: LogicalCpuId, ticks: usize) {
    let mut lock = CPU_STATS.lock();
    let Some(stats) = lock.get_mut(&cpu_id) else {
        warn!("could not add time for cpu {cpu_id}: cpu is not registered");
        return;
    };

    match stats.state {
        CpuState::Idle => stats.idle += ticks,
        CpuState::User => stats.user += ticks,
        CpuState::Kernel => stats.kernel += ticks,
    }
}

pub fn add_irq(cpu_id: LogicalCpuId, irq: u8) {
    IRQ_COUNT.lock()[irq as usize] += 1;
    let mut lock = CPU_STATS.lock();
    let Some(stats) = lock.get_mut(&cpu_id) else {
        warn!("could not set cpu state for cpu {cpu_id}: cpu is not registered");
        return;
    };
    stats.irq += 1;
}

pub fn irq_counts() -> Vec<u64> {
    IRQ_COUNT.lock().to_vec()
}

impl Display for CpuStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "cpu{} {} {} {} {} {}",
            self.id.get(),
            self.user,
            self.nice,
            self.kernel,
            self.idle,
            self.irq
        )
    }
}
