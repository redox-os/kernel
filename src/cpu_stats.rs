use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

use alloc::string::String;
#[cfg(feature = "sys_stat")]
use alloc::vec::Vec;

use crate::cpu_set::LogicalCpuId;

/// The number of times (overall) where a CPU switched from one context to another.
static CONTEXT_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);
/// Number of times each Interrupt happened.
static IRQ_COUNT: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
/// Number of contexts that were created.
static CONTEXTS_COUNT: AtomicU64 = AtomicU64::new(0);

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
    user: AtomicUsize,
    /// Number of ticks spent on Niced userspace contexts
    nice: AtomicUsize,
    /// Number of ticks spent on kernel contexts
    kernel: AtomicUsize,
    /// Number of ticks spent idle
    idle: AtomicUsize,
    /// Number of times the CPU handled an interrupt
    irq: AtomicUsize,
    /// Current state of the CPU
    state: AtomicU8,
}

pub struct CpuStatsData {
    /// Number of ticks spent on userspace contexts
    pub user: usize,
    /// Number of ticks spent on Niced userspace contexts
    pub nice: usize,
    /// Number of ticks spent on kernel contexts
    pub kernel: usize,
    /// Number of ticks spent idle
    pub idle: usize,
    /// Number of times the CPU handled an interrupt
    pub irq: usize,
}

impl CpuStats {
    /// Set the CPU's current state
    ///
    /// # Parameters
    /// * `new_state` - The state of the CPU for the following ticks.
    #[inline]
    pub fn set_state(&self, new_state: CpuState) {
        if cfg!(not(feature = "sys_stat")) {
            return;
        }

        self.state.store(new_state as u8, Ordering::Relaxed);
    }

    /// Increments time statistics of a CPU
    ///
    /// Which statistic is incremented depends on the [`State`] of the CPU.
    ///
    /// # Parameters
    /// * `ticks` - NUmber of ticks to add.
    #[inline]
    pub fn add_time(&self, ticks: usize) {
        if cfg!(not(feature = "sys_stat")) {
            return;
        }

        match self.state.load(Ordering::Relaxed) {
            val if val == CpuState::Idle as u8 => self.idle.fetch_add(ticks, Ordering::Relaxed),
            val if val == CpuState::User as u8 => self.user.fetch_add(ticks, Ordering::Relaxed),
            val if val == CpuState::Kernel as u8 => self.kernel.fetch_add(ticks, Ordering::Relaxed),
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
        if cfg!(not(feature = "sys_stat")) {
            return;
        }

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

impl Into<CpuStatsData> for &CpuStats {
    fn into(self) -> CpuStatsData {
        CpuStatsData {
            user: self.user.load(Ordering::Relaxed),
            nice: self.nice.load(Ordering::Relaxed),
            kernel: self.kernel.load(Ordering::Relaxed),
            idle: self.idle.load(Ordering::Relaxed),
            irq: self.irq.load(Ordering::Relaxed),
        }
    }
}

/// Add a context switch to the count.
#[inline]
pub fn add_context_switch() {
    if cfg!(not(feature = "sys_stat")) {
        return;
    }

    CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Get the number of context switches.
#[cfg(feature = "sys_stat")]
pub fn get_context_switch_count() -> u64 {
    CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed)
}

/// Add a context creation to the count.
#[inline]
pub fn add_context() {
    if cfg!(not(feature = "sys_stat")) {
        return;
    }

    CONTEXTS_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Get the number of contexts created.
#[cfg(feature = "sys_stat")]
pub fn get_contexts_count() -> u64 {
    CONTEXTS_COUNT.load(Ordering::Relaxed)
}

/// Get the count of each interrupt.
#[cfg(feature = "sys_stat")]
pub fn irq_counts() -> Vec<u64> {
    IRQ_COUNT
        .iter()
        .map(|count| count.load(Ordering::Relaxed))
        .collect()
}
