use crate::{
    interrupt::stack_trace,
    ptrace,
    syscall::flag::*
};

extern {
    fn ksignal(signal: usize);
}

interrupt_stack!(divide_by_zero, stack, {
    println!("Divide by zero");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_stack!(debug, stack, {
    let mut handled = false;

    let guard = ptrace::set_process_regs(stack);

    // Disable singlestep before there is a breakpoint, since the breakpoint
    // handler might end up setting it again but unless it does we want the
    // default to be false.
    let had_singlestep = stack.iret.rflags & (1 << 8) == 1 << 8;
    stack.set_singlestep(false);

    if ptrace::breakpoint_callback(PTRACE_STOP_SINGLESTEP, None).is_some() {
        handled = true;
    } else {
        // There was no breakpoint, restore original value
        stack.set_singlestep(had_singlestep);
    }

    drop(guard);

    if !handled {
        println!("Debug trap");
        stack.dump();
        ksignal(SIGTRAP);
    }
});

interrupt_stack!(non_maskable, stack, {
    println!("Non-maskable interrupt");
    stack.dump();
});

interrupt_stack!(breakpoint, stack, {
    // The processor lets RIP point to the instruction *after* int3, so
    // unhandled breakpoint interrupt don't go in an infinite loop. But we
    // throw SIGTRAP anyway, so that's not a problem.
    //
    // We have the following code to prevent
    // - RIP from going out of sync with instructions
    // - The user having to do 2 syscalls to replace the instruction at RIP
    // - Having more compatibility glue for GDB than necessary
    //
    // Let's just follow Linux convention and let RIP be RIP-1, point to the
    // int3 instruction. After all, it's the sanest thing to do.
    stack.iret.rip -= 1;

    let guard = ptrace::set_process_regs(stack);

    if ptrace::breakpoint_callback(PTRACE_STOP_BREAKPOINT, None).is_none() {
        drop(guard);

        println!("Breakpoint trap");
        stack.dump();
        ksignal(SIGTRAP);
    }
});

interrupt_stack!(overflow, stack, {
    println!("Overflow trap");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_stack!(bound_range, stack, {
    println!("Bound range exceeded fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_stack!(invalid_opcode, stack, {
    println!("Invalid opcode fault");
    stack.dump();
    stack_trace();
    ksignal(SIGILL);
});

interrupt_stack!(device_not_available, stack, {
    println!("Device not available fault");
    stack.dump();
    stack_trace();
    ksignal(SIGILL);
});

interrupt_error!(double_fault, stack, {
    println!("Double fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(invalid_tss, stack, {
    println!("Invalid TSS fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(segment_not_present, stack, {
    println!("Segment not present fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(stack_segment, stack, {
    println!("Stack segment fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(protection, stack, {
    println!("Protection fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(page, stack, {
    let cr2: usize;
    asm!("mov rax, cr2" : "={rax}"(cr2) : : : "intel", "volatile");
    println!("Page fault: {:>016X}", cr2);
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_stack!(fpu, stack, {
    println!("FPU floating point fault");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_error!(alignment_check, stack, {
    println!("Alignment check fault");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});

interrupt_stack!(machine_check, stack, {
    println!("Machine check fault");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});

interrupt_stack!(simd, stack, {
    println!("SIMD floating point fault");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_stack!(virtualization, stack, {
    println!("Virtualization fault");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});

interrupt_error!(security, stack, {
    println!("Security exception");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});
