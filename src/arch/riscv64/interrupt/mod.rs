//! Interrupt instructions

#[macro_use]
pub mod handler;

pub mod irq;
pub mod trace;

pub use self::handler::InterruptStack;
pub use self::trace::stack_trace;

/// Clear interrupts
#[inline(always)]
pub unsafe fn disable() {
    asm!("csrw mie, 0", options(nomem, nostack));
}

/// Set interrupts
#[inline(always)]
pub unsafe fn enable() {
    asm!("csrw mie, 1", options(nomem, nostack));
}

/// Set interrupts and halt
/// This will atomically wait for the next interrupt
/// Performing enable followed by halt is not guaranteed to be atomic, use this instead!
#[inline(always)]
pub unsafe fn enable_and_halt() {
    asm!("csrw mie, 1", "wfi", options(nomem, nostack));
}

/// Set interrupts and nop
/// This will enable interrupts and allow the IF flag to be processed
/// Simply enabling interrupts does not gurantee that they will trigger, use this instead!
#[inline(always)]
pub unsafe fn enable_and_nop() {
    asm!("csrw mie, 1", "nop", options(nomem, nostack));
}

/// Halt instruction
#[inline(always)]
pub unsafe fn halt() {
    asm!("wfi", options(nomem, nostack));
}

/// Pause instruction
/// Safe because it is similar to a NOP, and has no memory effects
#[inline(always)]
pub fn pause() {
    //TODO
}

pub fn available_irqs_iter(cpu_id: usize) -> impl Iterator<Item = u8> + 'static {
    0..0
}

pub fn bsp_apic_id() -> Option<u32> {
    //TODO
    None
}

#[inline]
pub fn is_reserved(cpu_id: usize, index: u8) -> bool {
    //TODO
    true
}

#[inline]
pub fn set_reserved(cpu_id: usize, index: u8, reserved: bool) {
    //TODO
}
