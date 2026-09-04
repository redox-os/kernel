use crate::{
    cpu_set::LogicalCpuId,
    memory::{Enomem, RaiiFrame, RmmA, RmmArch},
    percpu::PercpuBlock,
};

#[cfg(not(test))]
impl PercpuBlock {
    pub fn current() -> &'static Self {
        unsafe { &*(crate::arch::device::cpu::registers::control_regs::tpidr_el1() as *const Self) }
    }
}

#[cold]
pub unsafe fn init(cpu_id: LogicalCpuId) {
    unsafe {
        let frame = prepare(cpu_id).expect("failed to allocate percpu memory");
        install(&frame);

        // The current CPU owns this block until shutdown. AP boot slots retain
        // their RaiiFrame instead, so a failed preparation can unwind cleanly.
        let _ = frame.take();
    }
}

pub(crate) fn prepare(cpu_id: LogicalCpuId) -> Result<RaiiFrame, Enomem> {
    assert!(size_of::<PercpuBlock>() <= crate::memory::PAGE_SIZE);

    let frame = RaiiFrame::allocate()?;
    let virt = RmmA::phys_to_virt(frame.get().base()).data() as *mut PercpuBlock;
    unsafe { virt.write(PercpuBlock::init(cpu_id)) };
    Ok(frame)
}

/// Installs a block prepared for the CPU that is currently executing.
///
/// # Safety
///
/// `frame` must have been prepared for this CPU and must remain allocated for
/// as long as the CPU can execute kernel code.
pub(crate) unsafe fn install(frame: &RaiiFrame) {
    let virt = RmmA::phys_to_virt(frame.get().base()).data() as *mut PercpuBlock;
    unsafe { install_address(virt) };
}

/// Installs an initialized per-CPU block at a stable kernel virtual address.
///
/// # Safety
///
/// `virt` must refer to a live `PercpuBlock` prepared for the executing CPU.
pub(crate) unsafe fn install_address(virt: *mut PercpuBlock) {
    unsafe {
        crate::arch::device::cpu::registers::control_regs::tpidr_el1_write(virt as u64);
        crate::percpu::init_tlb_shootdown((*virt).cpu_id, virt);
    }
}

/// Detects a spin loop that has run far longer than any legitimate SMP
/// handshake should take, so a stuck TLB shootdown or context-switch lock
/// produces one diagnostic instead of hanging silently.
pub(crate) struct StallWatch {
    started: u64,
    limit: u64,
    reported: bool,
}

impl StallWatch {
    pub(crate) fn start(seconds: u64) -> Self {
        use crate::arch::device::cpu::registers::control_regs;
        let started = unsafe { control_regs::cntvct_el0() };
        let limit = u64::from(unsafe { control_regs::cntfrq_el0() }).saturating_mul(seconds);
        Self {
            started,
            limit,
            reported: false,
        }
    }

    /// Returns `true` the first time the watch is polled past its timeout;
    /// `false` otherwise, including on later polls of an already-reported
    /// stall.
    pub(crate) fn stalled(&mut self) -> bool {
        if self.reported || self.limit == 0 {
            return false;
        }
        let elapsed = unsafe { crate::arch::device::cpu::registers::control_regs::cntvct_el0() }
            .wrapping_sub(self.started);
        if elapsed < self.limit {
            return false;
        }
        self.reported = true;
        true
    }
}
