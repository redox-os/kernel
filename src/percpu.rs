use core::sync::atomic::{AtomicUsize, AtomicPtr, Ordering};

use crate::cpu_set::MAX_CPU_COUNT;
use crate::{context::switch::ContextSwitchPercpu, cpu_set::LogicalCpuId};

/// The percpu block, that stored all percpu variables.
pub struct PercpuBlock {
    /// A unique immutable number that identifies the current CPU - used for scheduling
    pub cpu_id: LogicalCpuId,

    /// Context management
    pub switch_internals: ContextSwitchPercpu,

    // TODO: This lock can probably be relaxed further, but verify correctness first.

    // The NMI lock. Can be set by any CPU, but can only be cleared by the CPU this percpu block
    // refers to. Multiple flags can be set simultaneously, but NMI senders need to wait for the
    // flag to be cleared if it was already set.
    pub nmi_flags_lock: AtomicUsize,

    // TODO: Put mailbox queues here, e.g. for TLB shootdown? Just be sure to 128-byte align it
    // first to avoid cache invalidation.
    #[cfg(feature = "profiling")]
    pub profiling: Option<&'static crate::profiling::RingBuffer>,
}

const NULL: AtomicPtr<PercpuBlock> = AtomicPtr::new(core::ptr::null_mut());
static ALL_PERCPU_BLOCKS: [AtomicPtr<PercpuBlock>; MAX_CPU_COUNT as usize] = [NULL; MAX_CPU_COUNT as usize];

// PercpuBlock::current() is implemented somewhere in the arch-specific modules

bitflags::bitflags! {
    struct NmiReasons: usize {
        const TLB_SHOOTDOWN = 1;

        // TODO: Profiling code wakes all CPUs up, so use a global and percpu ack counter for that.
        //
        //#[cfg(feature = "profiling")]
        //const PROFILING = 1 << 32;
    }
}

#[cfg(not(feature = "multi_core"))]
pub fn shootdown_tlb_ipi(_target: Option<LogicalCpuId>) {}

#[cfg(feature = "multi_core")]
pub fn shootdown_tlb_ipi(target: Option<LogicalCpuId>) {
    if let Some(target) = target {
        let Some(percpublock) = (unsafe { ALL_PERCPU_BLOCKS[target.get() as usize].load(Ordering::Acquire).as_ref() }) else {
            return;
        };
        let bit = NmiReasons::TLB_SHOOTDOWN.bits();

        while percpublock.nmi_flags_lock.fetch_or(bit, Ordering::Release) & bit == bit {
            // Load is faster than CAS or on x86, LOCK BTS
            while percpublock.nmi_flags_lock.load(Ordering::Relaxed) & bit == bit {
                core::hint::spin_loop();
            }
        }
    } else {
        for id in 0..crate::cpu_count() {
            // TODO: Optimize: use global counter and percpu ack counters.
            shootdown_tlb_ipi(Some(LogicalCpuId::new(id)));
        }
    }
}
