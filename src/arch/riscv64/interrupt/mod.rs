use core::arch::asm;

#[macro_use]
mod handler;

mod exception;
pub mod syscall;
pub mod trace;

pub use exception::exception_handler;
pub use handler::InterruptStack;

/// Clear interrupts
#[inline(always)]
pub unsafe fn disable() {
    unsafe { asm!("csrci sstatus, 1 << 1") }
}

/// Set interrupts
#[inline(always)]
pub unsafe fn enable() {
    unsafe { asm!("csrsi sstatus, 1 << 1") }
}

/// Set interrupts and halt
/// This will atomically wait for the next interrupt
/// Performing enable followed by halt is not guaranteed to be atomic, use this instead!
#[inline(always)]
pub unsafe fn enable_and_halt() {
    unsafe { asm!("wfi", "csrsi sstatus, 1 << 1", "nop") }
}

/// Set interrupts and nop
/// This will enable interrupts and allow the IF flag to be processed
/// Simply enabling interrupts does not gurantee that they will trigger, use this instead!
#[inline(always)]
pub unsafe fn enable_and_nop() {
    unsafe { asm!("csrsi sstatus, 1 << 1", "nop") }
}

/// Halt instruction
#[inline(always)]
pub unsafe fn halt() {
    unsafe { asm!("wfi", options(nomem, nostack)) }
}
