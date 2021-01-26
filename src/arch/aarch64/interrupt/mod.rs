//! Interrupt instructions

#[macro_use]
pub mod handler;

pub mod exception;
pub mod irq;
pub mod syscall;
pub mod trace;

pub use self::handler::InterruptStack;
pub use self::trace::stack_trace;

/// Clear interrupts
#[inline(always)]
pub unsafe fn disable() {
    llvm_asm!("msr daifset, #2");
}

/// Set interrupts
#[inline(always)]
pub unsafe fn enable() {
    llvm_asm!("msr daifclr, #2");
}

/// Set interrupts and halt
/// This will atomically wait for the next interrupt
/// Performing enable followed by halt is not guaranteed to be atomic, use this instead!
#[inline(always)]
pub unsafe fn enable_and_halt() {
    llvm_asm!("msr daifclr, #2");
    llvm_asm!("wfi");
}

/// Set interrupts and nop
/// This will enable interrupts and allow the IF flag to be processed
/// Simply enabling interrupts does not gurantee that they will trigger, use this instead!
#[inline(always)]
pub unsafe fn enable_and_nop() {
    llvm_asm!("msr daifclr, #2");
    llvm_asm!("nop");
}

/// Halt instruction
#[inline(always)]
pub unsafe fn halt() {
    llvm_asm!("wfi");
}

/// Pause instruction
/// Safe because it is similar to a NOP, and has no memory effects
#[inline(always)]
pub fn pause() {
    unsafe { llvm_asm!("nop") };
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
