use crate::{
    arch::{gdt, interrupt::InterruptStack},
    context,
    ptrace,
    syscall,
    syscall::flag::{PTRACE_FLAG_IGNORE, PTRACE_STOP_PRE_SYSCALL, PTRACE_STOP_POST_SYSCALL},
};
use x86::msr;

pub unsafe fn init() {
    msr::wrmsr(msr::IA32_STAR, ((gdt::GDT_KERNEL_CODE as u64) << 3) << 32);
    msr::wrmsr(msr::IA32_LSTAR, syscall_instruction as u64);
    msr::wrmsr(msr::IA32_FMASK, 0x0300); // Clear trap flag and interrupt enable
    msr::wrmsr(msr::IA32_KERNEL_GSBASE, &gdt::TSS as *const _ as u64);

    let efer = msr::rdmsr(msr::IA32_EFER);
    msr::wrmsr(msr::IA32_EFER, efer | 1);
}

macro_rules! with_interrupt_stack {
    (|$stack:ident| $code:block) => {{
        let allowed = ptrace::breakpoint_callback(PTRACE_STOP_PRE_SYSCALL, None)
            .and_then(|_| ptrace::next_breakpoint().map(|f| !f.contains(PTRACE_FLAG_IGNORE)));

        if allowed.unwrap_or(true) {
            // If the syscall is `clone`, the clone won't return here. Instead,
            // it'll return early and leave any undropped values. This is
            // actually GOOD, because any references are at that point UB
            // anyway, because they are based on the wrong stack.
            let $stack = &mut *$stack;
            (*$stack).scratch.rax = $code;
        }

        ptrace::breakpoint_callback(PTRACE_STOP_POST_SYSCALL, None);
    }}
}

#[no_mangle]
pub unsafe extern "C" fn __inner_syscall_instruction(stack: *mut InterruptStack) {
    let _guard = ptrace::set_process_regs(stack);
    with_interrupt_stack!(|stack| {
        // Set a restore point for clone
        let rbp;
        asm!("" : "={rbp}"(rbp) : : : "intel", "volatile");

        let scratch = &stack.scratch;
        syscall::syscall(scratch.rax, scratch.rdi, scratch.rsi, scratch.rdx, scratch.r10, scratch.r8, rbp, stack)
    });
}

function!(syscall_instruction => {
    // Yes, this is magic. No, you don't need to understand
    "
        swapgs                    // Set gs segment to TSS
        mov gs:[28], rsp          // Save userspace rsp
        mov rsp, gs:[4]           // Load kernel rsp
        push 5 * 8 + 3            // Push userspace data segment
        push QWORD PTR gs:[28]    // Push userspace rsp
        mov QWORD PTR gs:[28], 0  // Clear userspace rsp
        push r11                  // Push rflags
        push 4 * 8 + 3            // Push userspace code segment
        push rcx                  // Push userspace return pointer
        swapgs                    // Restore gs
    ",

    // Push context registers
    "push rax\n",
    push_scratch!(),
    push_preserved!(),
    push_fs!(),

    // TODO: Map PTI
    // $crate::arch::x86_64::pti::map();

    // Call inner funtion
    "mov rdi, rsp\n",
    "call __inner_syscall_instruction\n",

    // TODO: Unmap PTI
    // $crate::arch::x86_64::pti::unmap();

    // Pop context registers
    pop_fs!(),
    pop_preserved!(),
    pop_scratch!(),

    // Return
    "iretq\n",
});

interrupt_stack!(syscall, |stack| {
    with_interrupt_stack!(|stack| {
        {
            let contexts = context::contexts();
            let context = contexts.current();
            if let Some(current) = context {
                let current = current.read();
                let name = current.name.lock();
                println!("Warning: Context {} used deprecated `int 0x80` construct", core::str::from_utf8(&name).unwrap_or("(invalid utf8)"));
            } else {
                println!("Warning: Unknown context used deprecated `int 0x80` construct");
            }
        }

        // Set a restore point for clone
        let rbp;
        asm!("" : "={rbp}"(rbp) : : : "intel", "volatile");

        let scratch = &stack.scratch;
        syscall::syscall(scratch.rax, stack.preserved.rbx, scratch.rcx, scratch.rdx, scratch.rsi, scratch.rdi, rbp, stack)
    })
});

function!(clone_ret => {
    // The address of this instruction is injected by `clone` in process.rs, on
    // top of the stack syscall->inner in this file, which is done using the rbp
    // register we save there.
    //
    // The top of our stack here is the address pointed to by rbp, which is:
    //
    // - the previous rbp
    // - the return location
    //
    // Our goal is to return from the parent function, inner, so we restore
    // rbp...
    "pop rbp\n",
    // ...and we return to the address at the top of the stack
    "ret\n",
});
