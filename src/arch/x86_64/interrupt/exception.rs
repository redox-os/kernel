use crate::{
    common::unique::Unique,
    context,
    interrupt::stack_trace,
    ptrace,
    syscall::flag::*
};

extern {
    fn ksignal(signal: usize);
}

interrupt_stack_p!(divide_by_zero, stack, {
    println!("Divide by zero");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_stack!(debug, stack, {
    match ptrace::breakpoint_callback_dryrun(true) {
        Some(_) => {
            {
                let contexts = context::contexts();
                if let Some(context) = contexts.current() {
                    let mut context = context.write();
                    if let Some(ref mut kstack) = context.kstack {
                        context.regs = Some((kstack.as_mut_ptr() as usize, Unique::new_unchecked(stack)));
                    }
                }
            }

            let had_singlestep = stack.iret.rflags & (1 << 8) == 1 << 8;
            stack.set_singlestep(false);
            if ptrace::breakpoint_callback(true).is_none() {
                // There is no guarantee that this is Some(_) just
                // because the dryrun is Some(_). So, if there wasn't
                // *actually* any breakpoint, restore the trap flag.
                stack.set_singlestep(had_singlestep);
            }

            {
                let contexts = context::contexts();
                if let Some(context) = contexts.current() {
                    let mut context = context.write();
                    context.regs = None;
                }
            }
        },
        None => {
            println!("Debug trap");
            stack.dump();
            ksignal(SIGTRAP);
        }
    }
});

interrupt_stack!(non_maskable, stack, {
    println!("Non-maskable interrupt");
    stack.dump();
});

interrupt_stack!(breakpoint, stack, {
    println!("Breakpoint trap");
    stack.dump();
    ksignal(SIGTRAP);
});

interrupt_stack_p!(overflow, stack, {
    println!("Overflow trap");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_stack_p!(bound_range, stack, {
    println!("Bound range exceeded fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_stack_p!(invalid_opcode, stack, {
    println!("Invalid opcode fault");
    stack.dump();
    stack_trace();
    ksignal(SIGILL);
});

interrupt_stack_p!(device_not_available, stack, {
    println!("Device not available fault");
    stack.dump();
    stack_trace();
    ksignal(SIGILL);
});

interrupt_error_p!(double_fault, stack, {
    println!("Double fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error_p!(invalid_tss, stack, {
    println!("Invalid TSS fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error_p!(segment_not_present, stack, {
    println!("Segment not present fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error_p!(stack_segment, stack, {
    println!("Stack segment fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error_p!(protection, stack, {
    println!("Protection fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error_p!(page, stack, {
    let cr2: usize;
    asm!("mov rax, cr2" : "={rax}"(cr2) : : : "intel", "volatile");
    println!("Page fault: {:>016X}", cr2);
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_stack_p!(fpu, stack, {
    println!("FPU floating point fault");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_error_p!(alignment_check, stack, {
    println!("Alignment check fault");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});

interrupt_stack_p!(machine_check, stack, {
    println!("Machine check fault");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});

interrupt_stack_p!(simd, stack, {
    println!("SIMD floating point fault");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_stack_p!(virtualization, stack, {
    println!("Virtualization fault");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});

interrupt_error_p!(security, stack, {
    println!("Security exception");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});
