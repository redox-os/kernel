use core::sync::atomic::{AtomicU64, Ordering};

use alloc::{string::String, vec::Vec};

use crate::cpu_set::LogicalCpuId;

/// The number of times (overall) where a CPU switched from one context to another.
static CONTEXT_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);
/// Number of times each Interrupt happened.
static IRQ_COUNT: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
/// Number of contexts that were created.
static CONTEXTS_COUNT: AtomicU64 = AtomicU64::new(0);

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
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuStats {
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
    /// Current state of the CPU
    pub state: CpuState,
}

impl CpuStats {
    /// Increments time statistics of a CPU
    ///
    /// Which statistic is incremented depends on the [`State`] of the CPU.
    ///
    /// # Parameters
    /// * `cpu_id` - ID of the CPU whose time stats to increment,
    /// * `ticks` - NUmber of ticks to add.
    pub fn add_time(&mut self, ticks: usize) {
        match self.state {
            CpuState::Idle => self.idle += ticks,
            CpuState::User => self.user += ticks,
            CpuState::Kernel => self.kernel += ticks,
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
    pub fn add_irq(&mut self, irq: u8) {
        IRQ_COUNT[irq as usize].fetch_add(1, Ordering::Relaxed);
        self.irq += 1;
    }

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

/// Add a context switch to the count.
pub fn add_context_switch() {
    CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Get the number of context switches.
pub fn get_context_switch_count() -> u64 {
    CONTEXT_SWITCH_COUNT.load(Ordering::Relaxed)
}

/// Add a context creation to the count.
pub fn add_context() {
    CONTEXTS_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Get the number of contexts created.
pub fn get_contexts_count() -> u64 {
    CONTEXTS_COUNT.load(Ordering::Relaxed)
}

/// Get the count of each interrupt.
pub fn irq_counts() -> Vec<u64> {
    IRQ_COUNT
        .iter()
        .map(|count| count.load(Ordering::Relaxed))
        .collect()
}
