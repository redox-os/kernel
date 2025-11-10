use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::cpu_set::LogicalCpuId;

// Note: Using AtomicUsize rather than AtomicU64 as 32bit x86 doesn't support the latter
/// The number of times (overall) where a CPU switched from one context to another.
static CONTEXT_SWITCH_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Number of times each Interrupt happened.
static IRQ_COUNT: [AtomicUsize; 256] = [const { AtomicUsize::new(0) }; 256];
/// Number of contexts that were created.
static CONTEXTS_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Current state of a CPU
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default)]
pub enum CpuState {
    /// Waiting for runnable context
    #[default]
    Idle = 0,
    /// Runnnig a kernel context
    Kernel = 1,
    /// Running a context in the userspace
    User = 2,
}

/// Statistics for the CPUs.
#[derive(Debug, Default)]
pub struct CpuStats {
    /// Number of ticks spent on userspace contexts
    user: AtomicU64,
    /// Number of ticks spent on Niced userspace contexts
    nice: AtomicU64,
    /// Number of ticks spent on kernel contexts
    kernel: AtomicU64,
    /// Number of ticks spent idle
    idle: AtomicU64,
    /// Number of times the CPU handled an interrupt
    irq: AtomicU64,
    /// Current state of the CPU
    state: AtomicU8,
}

impl CpuStats {
    pub const fn default() -> Self {
        Self {
            user: AtomicU64::new(0),
            nice: AtomicU64::new(0),
            kernel: AtomicU64::new(0),
            idle: AtomicU64::new(0),
            irq: AtomicU64::new(0),
            state: AtomicU8::new(0),
        }
    }
}

pub struct CpuStatsData {
    /// Number of ticks spent on userspace contexts
    pub user: u64,
    /// Number of ticks spent on Niced userspace contexts
    pub nice: u64,
    /// Number of ticks spent on kernel contexts
    pub kernel: u64,
    /// Number of ticks spent idle
    pub idle: u64,
    /// Number of times the CPU handled an interrupt
    pub irq: u64,
}

impl CpuStats {
    /// Set the CPU's current state
    ///
    /// # Parameters
    /// * `new_state` - The state of the CPU for the following ticks.
    #[inline]
    pub fn set_state(&self, new_state: CpuState) {
        self.state.store(new_state as u8, Ordering::Relaxed);
    }

    /// Increments time statistics of a CPU
    ///
    /// Which statistic is incremented depends on the [`State`] of the CPU.
    ///
    /// # Parameters
    /// * `nanos` - Number of nanoseconds to add.
    #[inline]
    pub fn add_time(&self, nanos: u64) {
        match self.state.load(Ordering::Relaxed) {
            val if val == CpuState::Idle as u8 => self.idle.fetch_add(nanos, Ordering::Relaxed),
            val if val == CpuState::User as u8 => self.user.fetch_add(nanos, Ordering::Relaxed),
            val if val == CpuState::Kernel as u8 => self.kernel.fetch_add(nanos, Ordering::Relaxed),
            _ => unreachable!("all possible values are covered"),
        };
    }

    /// Add an IRQ event to both the global count and the CPU that handled it.
    ///
    /// This should be called in all [`crate::arch::interrupt:irq::eoi`],
    /// for all architectures.
    ///
    /// # Parameters
    /// * `irq` - The ID of the interrupt that happened.
    #[inline]
    pub fn add_irq(&self, irq: u8) {
        IRQ_COUNT[irq as usize].fetch_add(1, Ordering::Relaxed);
        self.irq.fetch_add(1, Ordering::Relaxed);
    }
}

impl CpuStatsData {
    pub fn to_string(&self, cpu_id: LogicalCpuId) -> String {
        format!(
            "cpu{} {} {} {} {} {}",
            cpu_id.get(),
            self.user,
            self.nice,
            self.kernel,
            self.idle,
            self.irq,
        )
    }
}

impl From<&CpuStats> for CpuStatsData {
    fn from(val: &CpuStats) -> Self {
        CpuStatsData {
            user: val.user.load(Ordering::Relaxed),
            nice: val.nice.load(Ordering::Relaxed),
            kernel: val.kernel.load(Ordering::Relaxed),
            idle: val.idle.load(Ordering::Relaxed),
            irq: val.irq.load(Ordering::Relaxed),
        }
    }
}

/// Add a context switch to the count.
#[inline]
pub fn add_context_switch() {
    CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Get the number of context switches.
pub fn get_context_switch_count() -> usize {
    CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed)
}

/// Add a context creation to the count.
#[inline]
pub fn add_context() {
    CONTEXTS_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Get the number of contexts created.
pub fn get_contexts_count() -> usize {
    CONTEXTS_COUNT.load(Ordering::Relaxed)
}

/// Get the count of each interrupt.
pub fn irq_counts() -> Vec<usize> {
    IRQ_COUNT
        .iter()
        .map(|count| count.load(Ordering::Relaxed))
        .collect()
}
