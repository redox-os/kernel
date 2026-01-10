//! Interrupt instructions

pub mod exception;
pub mod ipi;
pub mod irq;
pub mod trace;

pub use super::idt::{available_irqs_iter, is_reserved, set_reserved};

/// Clear interrupts
#[inline(always)]
pub unsafe fn disable() {
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}

/// Set interrupts and halt
/// This will atomically wait for the next interrupt
/// Performing enable followed by halt is not guaranteed to be atomic, use this instead!
#[inline(always)]
pub unsafe fn enable_and_halt() {
    unsafe {
        core::arch::asm!("sti; hlt", options(nomem, nostack));
    }
}

/// Set interrupts and nop
/// This will enable interrupts and allow the IF flag to be processed
/// Simply enabling interrupts does not guarantee that they will trigger, use this instead!
#[inline(always)]
pub unsafe fn enable_and_nop() {
    unsafe {
        core::arch::asm!("sti; nop", options(nomem, nostack));
    }
}

/// Halt instruction
#[inline(always)]
pub unsafe fn halt() {
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}
