//! Interrupt instructions

use core::arch::asm;

#[macro_use]
pub mod handler;

pub mod exception;
pub mod irq;
pub mod syscall;
pub mod trace;

pub use self::handler::InterruptStack;

/// Clear interrupts
#[inline(always)]
pub unsafe fn disable() {
    unsafe {
        asm!("msr daifset, #2");
    }
}

/// Set interrupts and halt
/// This will atomically wait for the next interrupt
/// Performing enable followed by halt is not guaranteed to be atomic, use this instead!
#[inline(always)]
pub unsafe fn enable_and_halt() {
    unsafe {
        asm!("msr daifclr, #2", "nop");
    }
}

/// Set interrupts and nop
/// This will enable interrupts and allow the IF flag to be processed
/// Simply enabling interrupts does not gurantee that they will trigger, use this instead!
#[inline(always)]
pub unsafe fn enable_and_nop() {
    unsafe {
        asm!("msr daifclr, #2", "nop");
    }
}

/// Halt instruction
#[inline(always)]
pub unsafe fn halt() {
    unsafe {
        asm!("wfi");
    }
}

#[inline(always)]
pub unsafe fn init() {
    unsafe {
        // Setup interrupt handlers
        asm!(
            "
        ldr {tmp}, =exception_vector_base
        msr vbar_el1, {tmp}
        ",
            tmp = out(reg) _,
        );
    }
}
