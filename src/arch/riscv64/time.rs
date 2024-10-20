use core::{
    arch::asm,
    sync::atomic::{AtomicUsize, Ordering},
};

static MTIME_FREQ_HZ: AtomicUsize = AtomicUsize::new(0);

pub fn init(freq_hz: usize) {
    MTIME_FREQ_HZ.store(freq_hz, Ordering::Relaxed);
}

pub fn monotonic_absolute() -> u128 {
    let freq_hz = MTIME_FREQ_HZ.load(Ordering::Relaxed);
    if freq_hz > 0 {
        let counter: usize;
        unsafe {
            asm!(
            "rdtime t0",
            lateout("t0") counter
            );
        };
        counter as u128 * 1_000_000_000u128 / freq_hz as u128
    } else {
        0
    }
}
