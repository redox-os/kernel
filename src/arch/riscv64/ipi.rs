use core::sync::atomic::{AtomicUsize, Ordering};

use sbi_rt::HartMask;

use crate::{cpu_set::MAX_CPU_COUNT, percpu::PercpuBlock};

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IpiKind {
    Wakeup = 0x40,
    Tlb = 0x41,
    Switch = 0x42,
    Pit = 0x43,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IpiTarget {
    Current = 1,
    All = 2,
    Other = 3,
}
// technically the hart_id could be any arbitrarily large 64 bit value
static HART_MASKS: [AtomicUsize; MAX_CPU_COUNT as usize / 64] =
    [const { AtomicUsize::new(0) }; MAX_CPU_COUNT as usize / 64];

pub fn init(hart_id: usize) {
    assert!(hart_id < MAX_CPU_COUNT as usize);
    // debug!("ipi init from hart {}", hart_id);
    let mask_index = hart_id / 64;
    let bit_index = hart_id % 64;
    HART_MASKS[mask_index].fetch_or(1 << bit_index, Ordering::Relaxed);
}

#[inline(always)]
pub fn ipi(kind: IpiKind, target: IpiTarget) {
    if cfg!(not(feature = "multi_core")) {
        return;
    }

    let hart_id = PercpuBlock::current().misc_arch_info.hart_id;
    // debug!(
    //     "sending ipi {:?} from hart {} to {:?}",
    //     kind, hart_id, target
    // );

    let mut masks = if matches!(target, IpiTarget::Current) {
        [0usize; MAX_CPU_COUNT as usize / 64]
    } else {
        HART_MASKS.each_ref().map(|m| m.load(Ordering::Relaxed))
    };
    if !matches!(target, IpiTarget::All) {
        masks[hart_id / 64] ^= 1 << (hart_id % 64);
    }

    for (i, mask) in masks.into_iter().enumerate() {
        match kind {
            //IpiKind::Tlb => sbi_rt::remote_sfence_vma(HartMask::from_mask_base(mask, i * 64), 0, 0),
            IpiKind::Tlb | IpiKind::Wakeup | IpiKind::Switch | IpiKind::Pit => {
                sbi_rt::send_ipi(HartMask::from_mask_base(mask, i * 64))
            }
        }
        .into_result()
        .expect("");
    }
}

#[inline(always)]
pub fn ipi_single(kind: IpiKind, target: &crate::percpu::PercpuBlock) {
    if cfg!(not(feature = "multi_core")) {
        return;
    }

    let hart_id = target.misc_arch_info.hart_id;
    // debug!(
    //     "sending single ipi {:?} from hart {} to {:?}",
    //     kind,
    //     PercpuBlock::current().misc_arch_info.hart_id,
    //     hart_id
    // );

    let mut masks = [0; MAX_CPU_COUNT as usize / 64];
    masks[hart_id / 64] ^= 1 << (hart_id % 64);

    for (i, mask) in masks.into_iter().enumerate() {
        match kind {
            // IpiKind::Tlb => {
            //     sbi_rt::remote_sfence_vma(HartMask::from_mask_base(mask, i * 64), 0, usize::MAX)
            // }
            IpiKind::Tlb | IpiKind::Wakeup | IpiKind::Switch | IpiKind::Pit => {
                sbi_rt::send_ipi(HartMask::from_mask_base(mask, i * 64))
            }
        }
        .into_result()
        .expect("");
    }
}
