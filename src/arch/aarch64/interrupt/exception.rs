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

exception_stack!(synchronous_exception_at_el1_with_spx, |stack| {
    println!("Synchronous exception at EL1 with SPx");
    stack.dump();
    stack_trace();
    loop {}
});

exception_stack!(synchronous_exception_at_el0, |stack| {
    with_exception_stack!(|stack| {
        let fp;
        asm!("mov {}, fp", out(reg) fp);

        let exception_code = (stack.iret.esr_el1 & (0x3f << 26)) >> 26;
        if exception_code != 0b010101 {
            println!("FATAL: Not an SVC induced synchronous exception");
            stack.dump();
            stack_trace();

            println!("CPU {}, PID {:?}", cpu_id(), context::context_id());

            // This could deadlock, but at this point we are going to halt anyways
            {
                let contexts = context::contexts();
                if let Some(context_lock) = contexts.current() {
                    let context = context_lock.read();
                    println!("NAME: {}", *context.name.read());
                }
            }

            // Halt
            loop {}
        }

        let scratch = &stack.scratch;
        syscall::syscall(scratch.x8, scratch.x0, scratch.x1, scratch.x2, scratch.x3, scratch.x4, fp, stack)
    });
});

exception_stack!(unhandled_exception, |stack| {
    println!("Unhandled exception");
    stack.dump();
    stack_trace();
    loop {}
});
