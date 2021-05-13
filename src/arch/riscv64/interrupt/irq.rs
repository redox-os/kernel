
use core::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

//resets to 0 in context::switch()
pub static PIT_TICKS: AtomicUsize = ATOMIC_USIZE_INIT;

pub unsafe fn acknowledge(_irq: usize) {
    // TODO
}
