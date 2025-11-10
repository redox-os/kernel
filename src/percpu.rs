use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use rmm::Arch;
use syscall::PtraceFlags;

use crate::{
    arch::device::ArchPercpuMisc,
    context::{empty_cr3, memory::AddrSpaceWrapper, switch::ContextSwitchPercpu},
    cpu_set::{LogicalCpuId, MAX_CPU_COUNT},
    cpu_stats::{CpuStats, CpuStatsData},
    ptrace::Session,
    syscall::debug::SyscallDebugInfo,
};

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
    pub profiling: Option<&'static crate::profiling::RingBuffer>,

    pub ptrace_flags: Cell<PtraceFlags>,
    pub ptrace_session: RefCell<Option<Weak<Session>>>,
    pub inside_syscall: Cell<bool>,

    pub syscall_debug_info: Cell<SyscallDebugInfo>,

    pub misc_arch_info: crate::device::ArchPercpuMisc,

    pub stats: CpuStats,
}

static ALL_PERCPU_BLOCKS: [AtomicPtr<PercpuBlock>; MAX_CPU_COUNT as usize] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPU_COUNT as usize];

#[allow(unused)]
pub unsafe fn init_tlb_shootdown(id: LogicalCpuId, block: *mut PercpuBlock) {
    ALL_PERCPU_BLOCKS[id.get() as usize].store(block, Ordering::Release)
}

pub fn get_all_stats() -> Vec<(LogicalCpuId, CpuStatsData)> {
    let mut res = ALL_PERCPU_BLOCKS
        .iter()
        .filter_map(|block| unsafe { block.load(Ordering::Relaxed).as_ref() })
        .map(|block| {
            let stats = &block.stats;
            (block.cpu_id, stats.into())
        })
        .collect::<Vec<_>>();
    res.sort_unstable_by_key(|(id, _stats)| id.get());
    res
}

// PercpuBlock::current() is implemented somewhere in the arch-specific modules

pub fn shootdown_tlb_ipi(target: Option<LogicalCpuId>) {
    if cfg!(not(feature = "multi_core")) {
        return;
    }

    if let Some(target) = target {
        let my_percpublock = PercpuBlock::current();
        assert_ne!(target, my_percpublock.cpu_id);

        let Some(percpublock) = (unsafe {
            ALL_PERCPU_BLOCKS[target.get() as usize]
                .load(Ordering::Acquire)
                .as_ref()
        }) else {
            warn!("Trying to TLB shootdown a CPU that doesn't exist or isn't initialized.");
            return;
        };
        #[expect(clippy::bool_comparison)]
        while percpublock
            .wants_tlb_shootdown
            .swap(true, Ordering::Release)
            == true
        {
            // Load is faster than CAS or on x86, LOCK BTS
            while percpublock.wants_tlb_shootdown.load(Ordering::Relaxed) == true {
                my_percpublock.maybe_handle_tlb_shootdown();
                core::hint::spin_loop();
            }
        }

        crate::ipi::ipi_single(crate::ipi::IpiKind::Tlb, percpublock);
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
        #[expect(clippy::bool_comparison)]
        if self.wants_tlb_shootdown.swap(false, Ordering::Relaxed) == false {
            return;
        }

        // TODO: Finer-grained flush
        unsafe {
            crate::paging::RmmA::invalidate_all();
        }

        if let Some(addrsp) = &*self.current_addrsp.borrow() {
            addrsp.tlb_ack.fetch_add(1, Ordering::Release);
        }
    }
}
pub unsafe fn switch_arch_hook() {
    unsafe {
        let percpu = PercpuBlock::current();

        let cur_addrsp = percpu.current_addrsp.borrow();
        let next_addrsp = percpu.new_addrsp_tmp.take();

        let retain_pgtbl = match (&*cur_addrsp, &next_addrsp) {
            (Some(p), Some(n)) => Arc::ptr_eq(p, n),
            (Some(_), None) | (None, Some(_)) => false,
            (None, None) => true,
        };
        if retain_pgtbl {
            // If we are not switching to a different address space, we can simply return early.
            return;
        }
        if let Some(prev_addrsp) = &*cur_addrsp {
            prev_addrsp
                .acquire_read()
                .used_by
                .atomic_clear(percpu.cpu_id);
        }

        drop(cur_addrsp);

        // Tell future TLB shootdown handlers that old_addrsp_tmp is no longer the current address
        // space.
        *percpu.current_addrsp.borrow_mut() = next_addrsp;

        match &*percpu.current_addrsp.borrow() {
            Some(next_addrsp) => {
                let next = next_addrsp.acquire_read();

                next.used_by.atomic_set(percpu.cpu_id);
                next.table.utable.make_current();
            }
            _ => {
                crate::paging::RmmA::set_table(rmm::TableKind::User, empty_cr3());
            }
        }
    }
}
impl PercpuBlock {
    pub const fn init(cpu_id: LogicalCpuId) -> Self {
        Self {
            cpu_id,
            switch_internals: ContextSwitchPercpu::default(),
            current_addrsp: RefCell::new(None),
            new_addrsp_tmp: Cell::new(None),
            wants_tlb_shootdown: AtomicBool::new(false),
            ptrace_flags: Cell::new(PtraceFlags::empty()),
            ptrace_session: RefCell::new(None),
            inside_syscall: Cell::new(false),

            syscall_debug_info: Cell::new(SyscallDebugInfo::default()),

            profiling: None,

            misc_arch_info: ArchPercpuMisc::default(),

            stats: CpuStats::default(),
        }
    }
}
