//! Interrupt instructions

pub mod ipi;
pub mod trace;

pub use super::{
    device::local_apic::bsp_apic_id,
    idt::{available_irqs_iter, is_reserved, set_reserved},
};

/// Clear interrupts
#[inline(always)]
pub unsafe fn disable() {
    core::arch::asm!("cli", options(nomem, nostack));
}

/// Set interrupts and halt
/// This will atomically wait for the next interrupt
/// Performing enable followed by halt is not guaranteed to be atomic, use this instead!
#[inline(always)]
pub unsafe fn enable_and_halt() {
    core::arch::asm!("sti; hlt", options(nomem, nostack));
}

/// Set interrupts and nop
/// This will enable interrupts and allow the IF flag to be processed
/// Simply enabling interrupts does not gurantee that they will trigger, use this instead!
#[inline(always)]
pub unsafe fn enable_and_nop() {
    core::arch::asm!("sti; nop", options(nomem, nostack));
}

/// Halt instruction
#[inline(always)]
pub unsafe fn halt() {
    core::arch::asm!("hlt", options(nomem, nostack));
}

/// Pause instruction
/// Safe because it is similar to a NOP, and has no memory effects
#[inline(always)]
pub fn pause() {
    unsafe {
        core::arch::asm!("pause", options(nomem, nostack));
    }
}
