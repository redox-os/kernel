use syscall::Exception;
use x86::irq::PageFaultError;

use crate::{
    arch::x86_shared::interrupt, context::signal::excp_handler, memory::GenericPfFlags,
    paging::VirtualAddress, ptrace, sync::CleanLockToken, syscall::flag::*,
};

interrupt_stack!(divide_by_zero, |stack| {
    println!("Divide by zero");
    stack.trace();
    excp_handler(Exception {
        kind: 0,
        ..Default::default()
    });
});

interrupt_stack!(debug, @paranoid, |stack| {
    let mut handled = false;

    // Disable singlestep before there is a breakpoint, since the breakpoint
    // handler might end up setting it again but unless it does we want the
    // default to be false.
    #[cfg(target_arch = "x86")]
    let had_singlestep = stack.iret.eflags & (1 << 8) == 1 << 8;
    #[cfg(target_arch = "x86_64")]
    let had_singlestep = stack.iret.rflags & (1 << 8) == 1 << 8;
    stack.set_singlestep(false);

    let mut token = unsafe { CleanLockToken::new() };
    if ptrace::breakpoint_callback(PTRACE_STOP_SINGLESTEP, None, &mut token).is_some() {
        handled = true;
    } else {
        // There was no breakpoint, restore original value
        stack.set_singlestep(had_singlestep);
    }

    if !handled {
        println!("Debug trap");
        stack.dump();
        excp_handler(Exception {
            kind: 1,
            ..Default::default()
        });
    }
});

interrupt_stack!(non_maskable, @paranoid, |stack| {
    #[cfg(feature = "profiling")]
    unsafe { crate::profiling::nmi_handler(stack) };

    #[cfg(not(feature = "profiling"))]
    {
        // TODO: This will likely deadlock
        println!("Non-maskable interrupt");
        stack.dump();
    }
});

interrupt_stack!(breakpoint, |stack| {
    // The processor lets EIP/RIP point to the instruction *after* int3, so
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
    #[cfg(target_arch = "x86")]
    {
        stack.iret.eip -= 1;
    }
    #[cfg(target_arch = "x86_64")]
    {
        stack.iret.rip -= 1;
    }

    let mut token = unsafe { CleanLockToken::new() };
    if ptrace::breakpoint_callback(PTRACE_STOP_BREAKPOINT, None, &mut token).is_none() {
        println!("Breakpoint trap");
        stack.dump();
        excp_handler(Exception {
            kind: 3,
            ..Default::default()
        });
    }
});

interrupt_stack!(overflow, |stack| {
    println!("Overflow trap");
    stack.trace();
    excp_handler(Exception {
        kind: 4,
        ..Default::default()
    });
});

interrupt_stack!(bound_range, |stack| {
    println!("Bound range exceeded fault");
    stack.trace();
    excp_handler(Exception {
        kind: 5,
        ..Default::default()
    });
});

interrupt_stack!(invalid_opcode, |stack| {
    println!("Invalid opcode fault");
    stack.trace();
    excp_handler(Exception {
        kind: 6,
        ..Default::default()
    });
});

interrupt_stack!(device_not_available, |stack| {
    println!("Device not available fault");
    stack.trace();
    excp_handler(Exception {
        kind: 7,
        ..Default::default()
    });
});

interrupt_error!(double_fault, |stack, _code| {
    println!("Double fault");
    stack.trace();
    unsafe {
        loop {
            interrupt::disable();
            interrupt::halt();
        }
    }
});

interrupt_error!(invalid_tss, |stack, code| {
    println!("Invalid TSS fault");
    stack.trace();
    excp_handler(Exception {
        kind: 10,
        code,
        ..Default::default()
    });
});

interrupt_error!(segment_not_present, |stack, code| {
    println!("Segment not present fault");
    stack.trace();
    excp_handler(Exception {
        kind: 11,
        code,
        ..Default::default()
    });
});

interrupt_error!(stack_segment, |stack, code| {
    println!("Stack segment fault");
    stack.trace();
    excp_handler(Exception {
        kind: 12,
        code,
        ..Default::default()
    });
});

interrupt_error!(protection, |stack, code| {
    println!("Protection fault code={:#0x}", code);
    stack.trace();
    excp_handler(Exception {
        kind: 13,
        code,
        ..Default::default()
    });
});

interrupt_error!(page, |stack, code| {
    let cr2 = VirtualAddress::new(unsafe { x86::controlregs::cr2() });
    let arch_flags = PageFaultError::from_bits_truncate(code as u32);
    let mut generic_flags = GenericPfFlags::empty();

    generic_flags.set(
        GenericPfFlags::PRESENT,
        arch_flags.contains(PageFaultError::P),
    );
    generic_flags.set(
        GenericPfFlags::INVOLVED_WRITE,
        arch_flags.contains(PageFaultError::WR),
    );
    generic_flags.set(
        GenericPfFlags::USER_NOT_SUPERVISOR,
        arch_flags.contains(PageFaultError::US),
    );
    generic_flags.set(
        GenericPfFlags::INVL,
        arch_flags.contains(PageFaultError::RSVD),
    );
    generic_flags.set(
        GenericPfFlags::INSTR_NOT_DATA,
        arch_flags.contains(PageFaultError::ID),
    );

    #[cfg(target_arch = "x86")]
    if crate::memory::page_fault_handler(&mut stack.inner, generic_flags, cr2).is_err() {
        println!("Page fault: {:>08X} {:#?}", cr2.data(), arch_flags);
        stack.trace();
        excp_handler(Exception {
            kind: 14,
            code,
            address: cr2.data(),
        });
    }

    #[cfg(target_arch = "x86_64")]
    if crate::memory::page_fault_handler(stack, generic_flags, cr2).is_err() {
        println!("Page fault: {:>016X} {:#?}", cr2.data(), arch_flags);
        stack.trace();
        excp_handler(Exception {
            kind: 14,
            code,
            address: cr2.data(),
        });
    }
});

interrupt_stack!(fpu_fault, |stack| {
    println!("FPU floating point fault");
    stack.trace();
    excp_handler(Exception {
        kind: 16,
        ..Default::default()
    });
});

interrupt_error!(alignment_check, |stack, code| {
    println!("Alignment check fault");
    stack.trace();
    excp_handler(Exception {
        kind: 17,
        code,
        ..Default::default()
    });
});

interrupt_stack!(machine_check, @paranoid, |stack| {
    println!("Machine check fault");
    stack.trace();
    unsafe {
        loop {
            interrupt::disable();
            interrupt::halt();
        }
    }
});

interrupt_stack!(simd, |stack| {
    println!("SIMD floating point fault");
    let mut mxcsr = 0_usize;
    unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) core::ptr::addr_of_mut!(mxcsr)) };
    println!("MXCSR {:#0x}", mxcsr);
    stack.trace();
    excp_handler(Exception {
        kind: 19,
        ..Default::default()
    });
});

interrupt_stack!(virtualization, |stack| {
    println!("Virtualization fault");
    stack.trace();
    unsafe {
        loop {
            interrupt::disable();
            interrupt::halt();
        }
    }
});

interrupt_error!(security, |stack, _code| {
    println!("Security exception");
    stack.trace();
    unsafe {
        loop {
            interrupt::disable();
            interrupt::halt();
        }
    }
});
