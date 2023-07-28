use rmm::VirtualAddress;

use crate::memory::{ArchIntCtx, GenericPfFlags};
use crate::{
    interrupt::stack_trace,
    syscall,
    syscall::flag::*,

    with_exception_stack,
    exception_stack,
};

use super::InterruptStack;

exception_stack!(synchronous_exception_at_el1_with_sp0, |stack| {
    println!("Synchronous exception at EL1 with SP0");
    stack.dump();
    stack_trace();
    loop {}
});

fn exception_code(esr: usize) -> u8 {
    ((esr >> 26) & 0x3f) as u8
}
fn iss(esr: usize) -> u32 {
    (esr & 0x01ff_ffff) as u32
}

unsafe fn far_el1() -> usize {
    let ret: usize;
    core::arch::asm!("mrs {}, far_el1", out(reg) ret);
    ret
}

unsafe fn instr_data_abort_inner(stack: &mut InterruptStack, from_user: bool, instr_not_data: bool) -> bool {
    let iss = iss(stack.iret.esr_el1);
    let fsc = iss & 0x3F;

    let was_translation_fault = fsc >= 0b000100 && fsc <= 0b000111;
    //let was_permission_fault = fsc >= 0b001101 && fsc <= 0b001111;
    let write_not_read_if_data = iss & (1 << 6) != 0;

    let mut flags = GenericPfFlags::empty();
    flags.set(GenericPfFlags::PRESENT, !was_translation_fault);

    // TODO: RMW instructions may "involve" writing to (possibly invalid) memory, but AArch64
    // doesn't appear to require that flag to be set if the read alone would trigger a fault.
    flags.set(GenericPfFlags::INVOLVED_WRITE, write_not_read_if_data && !instr_not_data);
    flags.set(GenericPfFlags::INSTR_NOT_DATA, instr_not_data);
    flags.set(GenericPfFlags::USER_NOT_SUPERVISOR, from_user);

    let faulting_addr = VirtualAddress::new(far_el1());

    crate::memory::page_fault_handler(stack, flags, faulting_addr).is_ok()
}

exception_stack!(synchronous_exception_at_el1_with_spx, |stack| {
    if !pf_inner(stack, exception_code(stack.iret.esr_el1)) {
        println!("Synchronous exception at EL1 with SPx");
        stack.dump();
        stack_trace();
        loop {}
    }
});
unsafe fn pf_inner(stack: &mut InterruptStack, ty: u8) -> bool {
    match ty {
        // "Data Abort taken from a lower Exception level"
        0b100100 => instr_data_abort_inner(stack, true, false),
        // "Data Abort taken without a change in Exception level"
        0b100101 => instr_data_abort_inner(stack, false, false),
        // "Instruction Abort taken from a lower Exception level"
        0b100000 => instr_data_abort_inner(stack, true, true),
        // "Instruction Abort taken without a change in Exception level"
        0b100001 => instr_data_abort_inner(stack, false, true),

        _ => return false,
    }
}

exception_stack!(synchronous_exception_at_el0, |stack| {
    match stack.iret.esr_el1 {
        0b010101 => with_exception_stack!(|stack| {
            let scratch = &stack.scratch;
            syscall::syscall(scratch.x8, scratch.x0, scratch.x1, scratch.x2, scratch.x3, scratch.x4, stack)
        }),

        ty => if !pf_inner(stack, ty as u8) {
            println!("FATAL: Not an SVC induced synchronous exception");
            println!("FAR_EL1: {:#0x}", far_el1());
            crate::debugger::debugger(None);
            stack.dump();
            stack_trace();
            crate::ksignal(SIGSEGV);
        }
    }
});

exception_stack!(unhandled_exception, |stack| {
    println!("Unhandled exception");
    stack.dump();
    stack_trace();
    loop {}
});

impl ArchIntCtx for InterruptStack {
    fn ip(&self) -> usize {
        self.iret.elr_el1
    }
    fn recover_and_efault(&mut self) {
        // Set the return value to nonzero to indicate usercopy failure (EFAULT), and emulate the
        // return instruction by setting the return pointer to the saved LR value.

        self.iret.elr_el1 = self.preserved.x30;
        self.scratch.x0 = 1;
    }
}
