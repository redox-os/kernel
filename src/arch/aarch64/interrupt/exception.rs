use core::arch::asm;

use crate::{
    context,
    cpu_id,
    interrupt::stack_trace,
    syscall,
    syscall::flag::*,

    with_exception_stack,
    exception_stack,
};

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

exception_stack!(synchronous_exception_at_el1_with_spx, |stack| {
    if exception_code(stack.iret.esr_el1) == 0b100101 {
        // "Data Abort taken without a change in Exception level"

        let iss = iss(stack.iret.esr_el1);

        let was_translation_fault = iss >= 0b000100 && iss <= 0b000111;
        let was_permission_fault = iss >= 0b001101 && iss <= 0b001111;

        extern "C" {
            static __usercopy_start: u8;
            static __usercopy_end: u8;
        }
        let usercopy = (&__usercopy_start as *const _ as usize)..(&__usercopy_end as *const _ as usize);

        if (was_translation_fault || was_permission_fault) && usercopy.contains(&{stack.iret.elr_el1}) {
            // This was a usercopy page fault. Set the return value to nonzero to indicate usercopy
            // failure (EFAULT), and emulate the return instruction by setting the return pointer
            // to the saved LR value.

            stack.iret.elr_el1 = stack.preserved.x30;
            stack.scratch.x0 = 1;

            return;
        }
    }

    println!("Synchronous exception at EL1 with SPx");
    stack.dump();
    stack_trace();
    loop {}
});

exception_stack!(synchronous_exception_at_el0, |stack| {
    with_exception_stack!(|stack| {
        if exception_code(stack.iret.esr_el1) != 0b010101 {
            println!("FATAL: Not an SVC induced synchronous exception");
            stack.dump();
            stack_trace();
            crate::ksignal(SIGSEGV);
            stack.scratch.x0
        } else {
            let scratch = &stack.scratch;
            syscall::syscall(scratch.x8, scratch.x0, scratch.x1, scratch.x2, scratch.x3, scratch.x4, stack)
        }
    });
});

exception_stack!(unhandled_exception, |stack| {
    println!("Unhandled exception");
    stack.dump();
    stack_trace();
    loop {}
});
