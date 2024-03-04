use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use alloc::sync::Arc;

use crate::context::memory::AddrSpaceWrapper;
use crate::cpu_set::MAX_CPU_COUNT;
use crate::{context::switch::ContextSwitchPercpu, cpu_set::LogicalCpuId};

/// The percpu block, that stored all percpu variables.
pub struct PercpuBlock {
    /// A unique immutable number that identifies the current CPU - used for scheduling
    pub cpu_id: LogicalCpuId,

    /// Context management
    pub switch_internals: ContextSwitchPercpu,

    pub current_addrsp: RefCell<Option<Arc<AddrSpaceWrapper>>>,
    pub new_addrsp_tmp: Cell<Option<Arc<AddrSpaceWrapper>>>,
    pub wants_tlb_shootdown: AtomicBool,

    // TODO: Put mailbox queues here, e.g. for TLB shootdown? Just be sure to 128-byte align it
    // first to avoid cache invalidation.
    #[cfg(feature = "profiling")]
    pub profiling: Option<&'static crate::profiling::RingBuffer>,
}

const NULL: AtomicPtr<PercpuBlock> = AtomicPtr::new(core::ptr::null_mut());
static ALL_PERCPU_BLOCKS: [AtomicPtr<PercpuBlock>; MAX_CPU_COUNT as usize] = [NULL; MAX_CPU_COUNT as usize];

pub unsafe fn init_tlb_shootdown(id: LogicalCpuId, block: *mut PercpuBlock) {
    ALL_PERCPU_BLOCKS[id.get() as usize].store(block, Ordering::Release)
}

// PercpuBlock::current() is implemented somewhere in the arch-specific modules

#[cfg(not(feature = "multi_core"))]
pub fn shootdown_tlb_ipi(_target: Option<LogicalCpuId>) {}

#[cfg(feature = "multi_core")]
pub fn shootdown_tlb_ipi(target: Option<LogicalCpuId>) {
    if let Some(target) = target {
        let my_percpublock = PercpuBlock::current();
        assert_ne!(target, my_percpublock.cpu_id);

        let Some(percpublock) = (unsafe { ALL_PERCPU_BLOCKS[target.get() as usize].load(Ordering::Acquire).as_ref() }) else {
            log::warn!("Trying to TLB shootdown a CPU that doesn't exist or isn't initialized.");
            return;
        };
        while percpublock.wants_tlb_shootdown.swap(true, Ordering::Release) == true {
            // Load is faster than CAS or on x86, LOCK BTS
            while percpublock.wants_tlb_shootdown.load(Ordering::Relaxed) == true {
                my_percpublock.maybe_handle_tlb_shootdown();
                core::hint::spin_loop();
            }
        }

        crate::ipi::ipi_single(crate::ipi::IpiKind::Tlb, target);
    } else {
        for id in 0..crate::cpu_count() {
            // TODO: Optimize: use global counter and percpu ack counters, send IPI using
            // destination shorthand "all CPUs".
            shootdown_tlb_ipi(Some(LogicalCpuId::new(id)));
        }
    }
}
impl PercpuBlock {
    pub fn maybe_handle_tlb_shootdown(&self) {
        if self.wants_tlb_shootdown.swap(false, Ordering::Relaxed) == false {
            return;
        }

        // TODO: Finer-grained flush
        unsafe {
            x86::tlb::flush_all();
        }

        if let Some(ref addrsp) = &*self.current_addrsp.borrow() {
            addrsp.tlb_ack.fetch_add(1, Ordering::Release);
        }
    }
}
