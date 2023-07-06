use rmm::TableKind;
use x86::irq::PageFaultError;

use crate::{
    interrupt::stack_trace,
    ptrace,
    syscall::flag::*,

    interrupt_stack,
    interrupt_error,
};

extern {
    fn ksignal(signal: usize);
}

interrupt_stack!(divide_by_zero, |stack| {
    println!("Divide by zero");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_stack!(debug, @paranoid, |stack| {
    let mut handled = false;

    // Disable singlestep before there is a breakpoint, since the breakpoint
    // handler might end up setting it again but unless it does we want the
    // default to be false.
    let had_singlestep = stack.iret.eflags & (1 << 8) == 1 << 8;
    stack.set_singlestep(false);

    if ptrace::breakpoint_callback(PTRACE_STOP_SINGLESTEP, None).is_some() {
        handled = true;
    } else {
        // There was no breakpoint, restore original value
        stack.set_singlestep(had_singlestep);
    }

    if !handled {
        println!("Debug trap");
        stack.dump();
        ksignal(SIGTRAP);
    }
});

interrupt_stack!(non_maskable, @paranoid, |stack| {
    println!("Non-maskable interrupt");
    stack.dump();
});

interrupt_stack!(breakpoint, |stack| {
    // The processor lets EIP point to the instruction *after* int3, so
    // unhandled breakpoint interrupt don't go in an infinite loop. But we
    // throw SIGTRAP anyway, so that's not a problem.
    //
    // We have the following code to prevent
    // - EIP from going out of sync with instructions
    // - The user having to do 2 syscalls to replace the instruction at EIP
    // - Having more compatibility glue for GDB than necessary
    //
    // Let's just follow Linux convention and let EIP be EIP-1, point to the
    // int3 instruction. After all, it's the sanest thing to do.
    stack.iret.eip -= 1;

    if ptrace::breakpoint_callback(PTRACE_STOP_BREAKPOINT, None).is_none() {
        println!("Breakpoint trap");
        stack.dump();
        ksignal(SIGTRAP);
    }
});

interrupt_stack!(overflow, |stack| {
    println!("Overflow trap");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_stack!(bound_range, |stack| {
    println!("Bound range exceeded fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_stack!(invalid_opcode, |stack| {
    println!("Invalid opcode fault");
    stack.dump();
    stack_trace();
    ksignal(SIGILL);
});

interrupt_stack!(device_not_available, |stack| {
    println!("Device not available fault");
    stack.dump();
    stack_trace();
    ksignal(SIGILL);
});

interrupt_error!(double_fault, |stack| {
    println!("Double fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(invalid_tss, |stack| {
    println!("Invalid TSS fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(segment_not_present, |stack| {
    println!("Segment not present fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(stack_segment, |stack| {
    println!("Stack segment fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(protection, |stack| {
    println!("Protection fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

#[naked]
unsafe extern "C" fn usercopy_trampoline() {
    core::arch::asm!("
        mov eax, 1

        pop esi
        pop edi

        ret 4
    ", options(noreturn));
}

interrupt_error!(page, |stack| {
    // TODO: Share code with x86_64?
    let cr2 = unsafe { x86::controlregs::cr2() };
    let flags = PageFaultError::from_bits_truncate(stack.code as u32);

    extern "C" {
        static __usercopy_start: u8;
        static __usercopy_end: u8;
    }
    let usercopy_region = (&__usercopy_start as *const u8 as usize)..(&__usercopy_end as *const u8 as usize);

    // TODO: Most likely not necessary, but maybe also check that cr2 is not too close to USER_END.
    let address_is_user = rmm::VirtualAddress::new(cr2).kind() == TableKind::User;

    let invalid_page_tables = flags.contains(PageFaultError::RSVD);
    let caused_by_user = flags.contains(PageFaultError::US);
    let caused_by_instr_fetch = flags.contains(PageFaultError::ID);

    if address_is_user && !caused_by_user && !caused_by_instr_fetch && !invalid_page_tables && usercopy_region.contains(&{ stack.inner.iret.eip }) {
        // Unlike on x86_64, Protected Mode interrupts will not save/restore esp and ss unless
        // privilege rings changed, which they won't here as we are catching a kernel-induced page
        // fault.
        //
        // Thus, it is only possible to change scratch/preserved registers, and EIP. While it may
        // be feasible to set ECX to zero to stop the REP MOVSB, or increase EIP by 2 (REP MOVSB is
        // f3 a4, i.e. 2 bytes), this trampoline allows any memcpy implementation, that reasonably
        // pushes preserved registers to the stack.
        stack.inner.iret.eip = usercopy_trampoline as usize;

        return;
    }

    println!("Page fault: {:>016X}", cr2);
    println!("  Present: {}", flags.contains(PageFaultError::P));
    println!("  Write: {}", flags.contains(PageFaultError::WR));
    println!("  User: {}", flags.contains(PageFaultError::US));
    println!("  Reserved write: {}", flags.contains(PageFaultError::RSVD));
    println!("  Instruction fetch: {}", flags.contains(PageFaultError::ID));

    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_stack!(fpu_fault, |stack| {
    println!("FPU floating point fault");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_error!(alignment_check, |stack| {
    println!("Alignment check fault");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});

interrupt_stack!(machine_check, @paranoid, |stack| {
    println!("Machine check fault");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});

interrupt_stack!(simd, |stack| {
    println!("SIMD floating point fault");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_stack!(virtualization, |stack| {
    println!("Virtualization fault");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});

interrupt_error!(security, |stack| {
    println!("Security exception");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});
