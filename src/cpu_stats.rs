use core::{
    fmt::Display,
    sync::atomic::{AtomicU64, Ordering},
};

use alloc::{string::String, vec::Vec};
use hashbrown::HashMap;
use log::warn;
use spin::{Lazy, Mutex};

use crate::{
    context::{contexts, ContextRef, Status},
    cpu_set::LogicalCpuId,
    syscall::error::Result,
    time::START,
};

/// Contains the statistics that depend on each individual CPU
static CPU_STATS: Lazy<Mutex<HashMap<LogicalCpuId, CpuStats>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
/// The number of times (overall) where a CPU switched from one context to another.
static CONTEXT_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);
/// Number of times each Interrupt happened.
static IRQ_COUNT: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
/// Number of processes that were created.
static PROCESSES_COUNT: AtomicU64 = AtomicU64::new(0);

/// Current state of a CPU
#[derive(Copy, Clone, Debug, Default)]
pub enum CpuState {
    /// Waiting for runnable context
    #[default]
    Idle,
    /// Runnnig a kernel context
    Kernel,
    /// Running a context in the userspace
    User,
}

/// Statistics for the CPUs.
///
/// At the moment, I/O wait and irq_soft are not tracked so will always be 0.
/// TODO: Implement I/O wait and Soft IRQ tracking if necessary
#[derive(Clone, Copy, Debug)]
pub struct CpuStats {
    /// Logical ID of the CPU
    pub id: LogicalCpuId,
    /// Number of ticks spent on userspace contexts
    pub user: usize,
    /// Number of ticks spent on Niced userspace contexts
    pub nice: usize,
    /// Number of ticks spent on kernel contexts
    pub kernel: usize,
    /// Number of ticks spent idle
    pub idle: usize,
    /// Number of ticks spent waiting for I/O
    pub io_wait: usize,
    /// Number of times the CPU handled an interrupt
    pub irq: usize,
    /// Number of times the CPU handled a soft interrupt
    pub irq_soft: usize,
    /// Current state of the CPU
    state: CpuState,
}

impl CpuStats {
    fn new(cpu_id: LogicalCpuId) -> Self {
        Self {
            id: cpu_id,
            ..Default::default()
        }
    }
}

/// Get the /scheme/proc/stat data as displayed to the user.
pub fn get_scheme_data() -> Result<Vec<u8>> {
    let start_time_sec = *START.lock() / 1_000_000_000;

    let (processes_running, processes_blocked) = get_processes_stats();
    let res = format!(
        "{}{}\n\
        ctxt: {}\n\
        btime: {start_time_sec}\n\
        processes: {}\n\
        procs_running: {processes_running}\n\
        procs_blocked: {processes_blocked}",
        get_cpu_stats(),
        get_irq_stats(),
        get_context_switch_count(),
        get_processes_count(),
    );

    Ok(res.into_bytes())
}

/// Formats CPU stats.
fn get_cpu_stats() -> String {
    let mut cpu_data = String::new();
    let stats = get_all();

    let mut total_user = 0;
    let mut total_nice = 0;
    let mut total_kernel = 0;
    let mut total_idle = 0;
    let mut total_io_wait = 0;
    let mut total_irq = 0;
    let mut total_soft = 0;
    for stat in stats {
        total_user += stat.user;
        total_nice += stat.nice;
        total_kernel += stat.kernel;
        total_idle += stat.idle;
        total_io_wait += stat.io_wait;
        total_irq += stat.irq;
        total_soft += stat.irq_soft;
        cpu_data += &format!("{stat}\n");
    }
    format!(
        "cpu  {total_user} {total_nice} {total_kernel} {total_idle} \
        {total_io_wait} {total_irq} {total_soft}\n\
        {cpu_data}"
    )
}

/// Formats IRQ stats.
fn get_irq_stats() -> String {
    let irq = irq_counts();
    let mut irq_total = 0;
    let per_irq = irq
        .iter()
        .map(|c| {
            irq_total += *c;
            format!("{c}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("intr {irq_total} {per_irq}")
}

/// Format processes stats.
fn get_processes_stats() -> (u64, u64) {
    let mut running = 0;
    let mut blocked = 0;

    let statuses = contexts()
        .iter()
        .filter_map(ContextRef::upgrade)
        .map(|context| context.read_arc().status.clone())
        .collect::<Vec<_>>();

    for status in statuses {
        if matches!(status, Status::Runnable) {
            running += 1;
        } else if !matches!(status, Status::Dead) {
            blocked += 1;
        }
    }
    (running, blocked)
}

/// Initializes stats for a logical CPU
///
/// # Parameters
/// * `cpu_id` - The logical ID of the CPU to initialize.
pub fn add_cpu(cpu_id: LogicalCpuId) {
    CPU_STATS.lock().insert(cpu_id, CpuStats::new(cpu_id));
}

/// Add a context switch to the count.
pub fn add_context_switch() {
    CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Get the number of context switches.
fn get_context_switch_count() -> u64 {
    CONTEXT_SWITCH_COUNT.load(Ordering::SeqCst)
}

/// Add a process creation to the count.
pub fn add_process() {
    PROCESSES_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Get the number of processes created.
fn get_processes_count() -> u64 {
    PROCESSES_COUNT.load(Ordering::SeqCst)
}

/// Get the stats for all the CPUs
fn get_all() -> Vec<CpuStats> {
    let mut res: Vec<_> = CPU_STATS.lock().values().cloned().collect();
    res.sort_unstable_by_key(|stat| stat.id.get());

    res
}

/// Sets the current state of a CPU.
///
/// This is useful with [`add_time`] to know which statistic to increment at the next
/// [`crate::switch::switch`].
///
/// # Parameters
/// * `cpu_id` - The id of the CPU whose state to change,
/// * `state` - The new state of the CPU.
pub fn set_state(cpu_id: LogicalCpuId, state: CpuState) {
    let mut lock = CPU_STATS.lock();
    let Some(stats) = lock.get_mut(&cpu_id) else {
        warn!("could not set cpu state for cpu {cpu_id}: cpu is not registered");
        return;
    };
    stats.state = state;
}

/// Increments time statistics of a CPU
///
/// Which statistic is incremented depends on the [`State`] of the CPU.
///
/// # Parameters
/// * `cpu_id` - ID of the CPU whose time stats to increment,
/// * `ticks` - NUmber of ticks to add.
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

/// Add an IRQ event to both the global count and the CPU that handled it.
///
/// This should be called in all [`crate::arch::interrupt:irq::eoi`],
/// for all architectures.
///
/// # Parameters
/// * `cpu_id` - The logical CPU ID handling the IRQ,
/// * `irq` - The ID of the interrupt that happened.
pub fn add_irq(cpu_id: LogicalCpuId, irq: u8) {
    IRQ_COUNT[irq as usize].fetch_add(1, Ordering::SeqCst);
    let mut lock = CPU_STATS.lock();
    let Some(stats) = lock.get_mut(&cpu_id) else {
        warn!("could not set cpu state for cpu {cpu_id}: cpu is not registered");
        return;
    };
    stats.irq += 1;
}

/// Get the count of each interrupt.
fn irq_counts() -> Vec<u64> {
    IRQ_COUNT
        .iter()
        .map(|count| count.load(Ordering::SeqCst))
        .collect()
}

impl Display for CpuStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "cpu{} {} {} {} {} {} {} {}",
            self.id.get(),
            self.user,
            self.nice,
            self.kernel,
            self.idle,
            self.io_wait,
            self.irq,
            self.irq_soft,
        )
    }
}

impl Default for CpuStats {
    fn default() -> Self {
        Self {
            id: LogicalCpuId::BSP,
            user: 0,
            nice: 0,
            kernel: 0,
            idle: 0,
            io_wait: 0,
            irq: 0,
            irq_soft: 0,
            state: CpuState::Idle,
        }
    }
}
