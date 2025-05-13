use crate::time::NANOS_PER_SEC;

pub fn monotonic_absolute() -> u128 {
    //TODO: aarch64 generic timer counter
    let ticks: usize;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) ticks) };
    let freq: usize;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };

    ticks as u128 * NANOS_PER_SEC / freq as u128
}
