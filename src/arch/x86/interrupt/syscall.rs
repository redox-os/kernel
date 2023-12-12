use crate::{
    arch::{gdt, interrupt::InterruptStack},
    context,
    ptrace,
    syscall,
    syscall::flag::{PTRACE_FLAG_IGNORE, PTRACE_STOP_PRE_SYSCALL, PTRACE_STOP_POST_SYSCALL},
};
use core::mem::offset_of;
use x86::{bits32::task::TaskStateSegment, msr, segmentation::SegmentSelector};

pub unsafe fn init() {}

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
            (*$stack).scratch.eax = $code;
        }

        ptrace::breakpoint_callback(PTRACE_STOP_POST_SYSCALL, None);
    }}
}

interrupt_stack!(syscall, |stack| {
    with_interrupt_stack!(|stack| {
        let scratch = &stack.scratch;
        let preserved = &stack.preserved;
        syscall::syscall(scratch.eax, preserved.ebx, scratch.ecx, scratch.edx, preserved.esi, preserved.edi, stack)
    })
});

#[naked]
pub unsafe extern "C" fn clone_ret() {
    core::arch::asm!(concat!(
    // The address of this instruction is injected by `clone` in process.rs, on
    // top of the stack syscall->inner in this file, which is done using the ebp
    // register we save there.
    //
    // The top of our stack here is the address pointed to by ebp, which is:
    //
    // - the previous ebp
    // - the return location
    //
    // Our goal is to return from the parent function, inner, so we restore
    // ebp...
    "pop ebp\n",
    // ...and we return to the address at the top of the stack
    "ret\n",
    ), options(noreturn));
}
