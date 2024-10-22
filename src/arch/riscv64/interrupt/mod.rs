use core::arch::asm;

#[macro_use]
mod handler;

mod exception;
pub mod syscall;
pub mod trace;

pub use handler::InterruptStack;

pub fn bsp_apic_id() -> Option<u32> {
    Some(0)
}

/// Clear interrupts
#[inline(always)]
pub unsafe fn disable() {
    asm!("csrci sstatus, 1 << 1")
}

/// Set interrupts
#[inline(always)]
pub unsafe fn enable() {
    asm!("csrsi sstatus, 1 << 1")
}

/// Set interrupts and halt
/// This will atomically wait for the next interrupt
/// Performing enable followed by halt is not guaranteed to be atomic, use this instead!
#[inline(always)]
pub unsafe fn enable_and_halt() {
    asm!("csrsi sstatus, 1 << 1", "wfi")
}

/// Set interrupts and nop
/// This will enable interrupts and allow the IF flag to be processed
/// Simply enabling interrupts does not gurantee that they will trigger, use this instead!
#[inline(always)]
pub unsafe fn enable_and_nop() {
    asm!("csrsi sstatus, 1 << 1", "nop")
}

/// Halt instruction
#[inline(always)]
pub unsafe fn halt() {
    asm!("wfi", options(nomem, nostack))
}

/// Pause instruction
/// Safe because it is similar to a NOP, and has no memory effects
#[inline(always)]
pub fn pause() {
    unsafe {
        // It's a hint instruction, safe to execute without Zihintpause extension
        asm!("pause", options(nomem, nostack));
    }
}

pub unsafe fn init() {
    // Setup interrupt handlers
    asm!(
        "la t0, exception_handler", // WARL=0 - direct mode combined handler
        "csrw stvec, t0"
    );
}
