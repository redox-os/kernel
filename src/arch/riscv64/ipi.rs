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

const MASKS_LEN: usize = MAX_CPU_COUNT.div_ceil(64) as usize;

// technically the hart_id could be any arbitrarily large 64 bit value
static HART_MASKS: [AtomicUsize; MASKS_LEN] = [const { AtomicUsize::new(0) }; MASKS_LEN];

pub fn init(hart_id: usize) {
    assert!(hart_id < MAX_CPU_COUNT as usize);
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
    assert!(hart_id / 64 < MASKS_LEN);

    // debug!(
    //     "sending ipi {:?} from hart {} to {:?}",
    //     kind, hart_id, target
    // );

    let mut masks = if matches!(target, IpiTarget::Current) {
        [0; MASKS_LEN]
    } else {
        HART_MASKS.each_ref().map(|m| m.load(Ordering::Relaxed))
    };
    if matches!(target, IpiTarget::Current | IpiTarget::Other) {
        masks[hart_id / 64] ^= 1 << (hart_id % 64);
    }

    send_ipi(kind, masks).expect("failed to send IPI through SBI");
}

#[inline(always)]
pub fn ipi_single(kind: IpiKind, target: &crate::percpu::PercpuBlock) {
    if cfg!(not(feature = "multi_core")) {
        return;
    }

    let hart_id = target.misc_arch_info.hart_id;
    assert!(hart_id / 64 < MASKS_LEN);

    // debug!(
    //     "sending single ipi {:?} from hart {} to {:?}",
    //     kind,
    //     PercpuBlock::current().misc_arch_info.hart_id,
    //     hart_id
    // );

    let mut masks = [0; MAX_CPU_COUNT as usize / 64];
    masks[hart_id / 64] ^= 1 << (hart_id % 64);

    send_ipi(kind, masks).unwrap();
}

fn send_ipi(kind: IpiKind, masks: impl IntoIterator<Item = usize>) -> Result<(), ()> {
    for (i, mask) in masks.into_iter().enumerate().filter(|(_, m)| *m != 0) {
        match kind {
            // TODO: use SBI for TLB shootdowns
            // IpiKind::Tlb => {
            //     sbi_rt::remote_sfence_vma(HartMask::from_mask_base(mask, i * 64), 0, usize::MAX)
            // }
            IpiKind::Tlb | IpiKind::Wakeup | IpiKind::Switch | IpiKind::Pit => {
                sbi_rt::send_ipi(HartMask::from_mask_base(mask, i * 64))
            }
        }
        .map_err(|_| ())?;
        // TODO: return the actual error
        // for some reason the error type is not exported by the sbi crate
    }
    Ok(())
}
