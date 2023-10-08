use core::sync::atomic::Ordering;

use x86::irq::PageFaultError;

use crate::memory::GenericPfFlags;
use crate::{
    interrupt::stack_trace,
    paging::VirtualAddress,
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
    let had_singlestep = stack.iret.rflags & (1 << 8) == 1 << 8;
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
    let Some(profiling) = crate::percpu::PercpuBlock::current().profiling else {
        return;
    };
    if stack.iret.cs & 0b00 == 0b11 {
        profiling.nmi_ucount.store(profiling.nmi_ucount.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        return;
    } else if stack.iret.rflags & (1 << 9) != 0 {
        // Interrupts were enabled, i.e. we were in kmain, so ignore.
        return;
    } else {
        profiling.nmi_kcount.store(profiling.nmi_kcount.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    };

    let mut buf = [0_usize; 32];
    buf[0] = stack.iret.rip & !(1<<63);
    buf[1] = x86::time::rdtsc() as usize;

    let mut bp = stack.preserved.rbp;

    let mut len = 2;

    for i in 2..32 {
        if bp.saturating_add(16) < crate::KERNEL_HEAP_OFFSET || bp >= crate::KERNEL_HEAP_OFFSET + crate::PML4_SIZE {
            break;
        }
        let ip = ((bp + 8) as *const usize).read();
        bp = (bp as *const usize).read();

        if ip < crate::kernel_executable_offsets::__text_start() || ip >= crate::kernel_executable_offsets::__text_end() {
            break;
        }
        buf[i] = ip;

        len = i + 1;
    }

    let _ = profiling.extend(&buf[..len]);
});

interrupt_stack!(breakpoint, |stack| {
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

interrupt_error!(double_fault, |stack, _code| {
    println!("Double fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(invalid_tss, |stack, _code| {
    println!("Invalid TSS fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(segment_not_present, |stack, _code| {
    println!("Segment not present fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(stack_segment, |stack, _code| {
    println!("Stack segment fault");
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(protection, |stack, code| {
    println!("Protection fault code={:#0x}", code);
    stack.dump();
    stack_trace();
    ksignal(SIGSEGV);
});

interrupt_error!(page, |stack, code| {
    let cr2 = VirtualAddress::new(unsafe { x86::controlregs::cr2() });
    let arch_flags = PageFaultError::from_bits_truncate(code as u32);
    let mut generic_flags = GenericPfFlags::empty();

    generic_flags.set(GenericPfFlags::PRESENT, arch_flags.contains(PageFaultError::P));
    generic_flags.set(GenericPfFlags::INVOLVED_WRITE, arch_flags.contains(PageFaultError::WR));
    generic_flags.set(GenericPfFlags::USER_NOT_SUPERVISOR, arch_flags.contains(PageFaultError::US));
    generic_flags.set(GenericPfFlags::INVL, arch_flags.contains(PageFaultError::RSVD));
    generic_flags.set(GenericPfFlags::INSTR_NOT_DATA, arch_flags.contains(PageFaultError::ID));

    if crate::memory::page_fault_handler(stack, generic_flags, cr2).is_err() {
        println!("Page fault: {:>016X} {:#?}", cr2.data(), arch_flags);
        stack.dump();
        stack_trace();
        ksignal(SIGSEGV);
    }
});

interrupt_stack!(fpu_fault, |stack| {
    println!("FPU floating point fault");
    stack.dump();
    stack_trace();
    ksignal(SIGFPE);
});

interrupt_error!(alignment_check, |stack, _code| {
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

interrupt_error!(security, |stack, _code| {
    println!("Security exception");
    stack.dump();
    stack_trace();
    ksignal(SIGBUS);
});
