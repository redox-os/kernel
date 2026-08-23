use core::sync::atomic::Ordering;

use crate::{
    context::switch::drain_ipi_context_wakeups, percpu::PercpuBlock, sync::CleanLockToken,
};

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IpiKind {
    Wakeup = 0,
    Tlb = 1,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IpiTarget {
    Other = 3,
}

#[inline(always)]
pub fn ipi(kind: IpiKind, target: IpiTarget) {
    if cfg!(not(feature = "multi_core")) || crate::cpu_count() <= 1 {
        return;
    }

    match target {
        IpiTarget::Other => {
            if let Err(error) = crate::arch::device::irqchip::send_sgi(kind as u8, None) {
                warn!("failed to send {:?} IPI: {:?}", kind, error);
            }
        }
    }
}

#[inline(always)]
pub fn ipi_single(kind: IpiKind, target: &PercpuBlock) {
    if cfg!(not(feature = "multi_core")) {
        return;
    }

    let target_mask = target
        .misc_arch_info
        .gic_target_mask
        .load(Ordering::Acquire);
    if let Err(error) = crate::arch::device::irqchip::send_sgi(kind as u8, Some(target_mask)) {
        warn!(
            "failed to send {:?} IPI to logical {}: {:?}",
            kind, target.cpu_id, error
        );
    }
}

pub(crate) fn handle(hwirq: u32, raw_iar: u32) -> bool {
    let handled = match hwirq {
        x if x == IpiKind::Wakeup as u32 => {
            // Cross-CPU scheduler wakeups are queued per CPU. Drain this CPU's
            // queue before completing the SGI, otherwise contexts assigned to
            // this CPU can remain blocked indefinitely.
            let mut token = unsafe { CleanLockToken::new() };
            drain_ipi_context_wakeups(&mut token);
            true
        }
        x if x == IpiKind::Tlb as u32 => {
            unsafe { core::arch::asm!("dmb ish", options(nostack, preserves_flags)) };
            PercpuBlock::current().maybe_handle_tlb_shootdown();
            true
        }
        _ => false,
    };

    if handled {
        crate::arch::device::irqchip::end_root(raw_iar);
    }
    handled
}
