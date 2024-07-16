use core::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use alloc::sync::{Arc, Weak};
use rmm::Arch;
use syscall::PtraceFlags;

use crate::{
    context::{empty_cr3, memory::AddrSpaceWrapper, switch::ContextSwitchPercpu},
    cpu_set::{LogicalCpuId, MAX_CPU_COUNT},
    ptrace::Session,
};

#[cfg(feature = "syscall_debug")]
use crate::syscall::debug::SyscallDebugInfo;

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

    pub ptrace_flags: Cell<PtraceFlags>,
    pub ptrace_session: RefCell<Option<Weak<Session>>>,
    pub inside_syscall: Cell<bool>,

    #[cfg(feature = "syscall_debug")]
    pub syscall_debug_info: Cell<SyscallDebugInfo>,

    pub misc_arch_info: crate::device::ArchPercpuMisc,
}

const NULL: AtomicPtr<PercpuBlock> = AtomicPtr::new(core::ptr::null_mut());
static ALL_PERCPU_BLOCKS: [AtomicPtr<PercpuBlock>; MAX_CPU_COUNT as usize] =
    [NULL; MAX_CPU_COUNT as usize];

#[allow(unused)]
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

        let Some(percpublock) = (unsafe {
            ALL_PERCPU_BLOCKS[target.get() as usize]
                .load(Ordering::Acquire)
                .as_ref()
        }) else {
            log::warn!("Trying to TLB shootdown a CPU that doesn't exist or isn't initialized.");
            return;
        };
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
            crate::paging::RmmA::invalidate_all();
        }

        if let Some(ref addrsp) = &*self.current_addrsp.borrow() {
            addrsp.tlb_ack.fetch_add(1, Ordering::Release);
        }
    }
}
pub unsafe fn switch_arch_hook() {
    let percpu = PercpuBlock::current();

    let cur_addrsp = percpu.current_addrsp.borrow();
    let next_addrsp = percpu.new_addrsp_tmp.take();

    let retain_pgtbl = match (&*cur_addrsp, &next_addrsp) {
        (Some(ref p), Some(ref n)) => Arc::ptr_eq(p, n),
        (Some(_), None) | (None, Some(_)) => false,
        (None, None) => true,
    };
    if retain_pgtbl {
        // If we are not switching to a different address space, we can simply return early.
    }
    if let Some(ref prev_addrsp) = &*cur_addrsp {
        prev_addrsp
            .acquire_read()
            .used_by
            .atomic_clear(percpu.cpu_id);
    }

    drop(cur_addrsp);

    // Tell future TLB shootdown handlers that old_addrsp_tmp is no longer the current address
    // space.
    *percpu.current_addrsp.borrow_mut() = next_addrsp;

    if let Some(next_addrsp) = &*percpu.current_addrsp.borrow() {
        let next = next_addrsp.acquire_read();

        next.used_by.atomic_set(percpu.cpu_id);
        next.table.utable.make_current();
    } else {
        crate::paging::RmmA::set_table(rmm::TableKind::User, empty_cr3());
    }
}
impl PercpuBlock {
    pub fn init(cpu_id: LogicalCpuId) -> Self {
        Self {
            cpu_id,
            switch_internals: Default::default(),
            current_addrsp: RefCell::new(None),
            new_addrsp_tmp: Cell::new(None),
            wants_tlb_shootdown: AtomicBool::new(false),
            ptrace_flags: Cell::new(Default::default()),
            ptrace_session: RefCell::new(None),
            inside_syscall: Cell::new(false),

            #[cfg(feature = "syscall_debug")]
            syscall_debug_info: Cell::new(SyscallDebugInfo::default()),

            #[cfg(feature = "profiling")]
            profiling: None,

            misc_arch_info: Default::default(),
        }
    }
}
