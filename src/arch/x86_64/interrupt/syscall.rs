use crate::arch::interrupt::InterruptStack;
use crate::arch::gdt;
use crate::syscall::flag::{PTRACE_FLAG_IGNORE, PTRACE_STOP_PRE_SYSCALL, PTRACE_STOP_POST_SYSCALL};
use crate::{ptrace, syscall};
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
    ($name:ident |$stack:ident| $code:block) => {{
        let _guard = ptrace::set_process_regs($stack);

        let allowed = ptrace::breakpoint_callback(PTRACE_STOP_PRE_SYSCALL, None)
            .and_then(|_| ptrace::next_breakpoint().map(|f| !f.contains(PTRACE_FLAG_IGNORE)));

        if allowed.unwrap_or(true) {
            paste::expr! {
                #[no_mangle]
                unsafe extern "C" fn [<__inner_stack_ $name>]($stack: &mut InterruptStack) -> usize {
                    $code
                }

                // A normal function call like inner(stack) is sadly not guaranteed
                // to map to a `call` instruction - it can also be a `jmp`. We want
                // this to definitely be its own call stack, to make `clone_ret`
                // work as expected.
                let ret;
                asm!(
                    concat!("call __inner_stack_", stringify!($name))
                        : "={rax}"(ret)
                        : "{rdi}"(&mut *$stack)
                        : /* no clobbers */
                        : "volatile", "intel"
                );

                (*$stack).scratch.rax = ret;
            }
        }

        ptrace::breakpoint_callback(PTRACE_STOP_POST_SYSCALL, None);
    }}
}

#[no_mangle]
pub unsafe extern "C" fn __inner_syscall_instruction(stack: *mut InterruptStack) {
    with_interrupt_stack!(syscall_instruction |stack| {
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
        push qword ptr gs:[28]    // Push userspace rsp
        mov qword ptr gs:[28], 0  // Clear userspace rsp
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
    with_interrupt_stack!(syscall |stack| {
        let rbp;
        asm!("" : "={rbp}"(rbp) : : : "intel", "volatile");

        let scratch = &stack.scratch;
        syscall::syscall(scratch.rax, stack.preserved.rbx, scratch.rcx, scratch.rdx, scratch.rsi, scratch.rdi, rbp, stack)
    })
});

function!(clone_ret => {
    // The C x86_64 ABI specifies that rbp is pushed to save the old call frame.
    // Popping rbp means we're using the parent's call frame and thus will not
    // only return from this function but also from the function above this one.

    // When this is called, the stack should have been
    // interrupt->inner->syscall->clone->clone_ret
    // then popped to
    // interrupt->inner->syscall
    // so this will return from "syscall".
    "pop rbx\n",
    "xor rax, rax\n",
    "ret\n",
});
