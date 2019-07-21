use crate::arch::macros::InterruptStack;
use crate::arch::{gdt, pti};
use crate::{ptrace, syscall};
use x86::shared::msr;

pub unsafe fn init() {
    msr::wrmsr(msr::IA32_STAR, ((gdt::GDT_KERNEL_CODE as u64) << 3) << 32);
    msr::wrmsr(msr::IA32_LSTAR, syscall_instruction as u64);
    msr::wrmsr(msr::IA32_FMASK, 0x0300); // Clear trap flag and interrupt enable
    msr::wrmsr(msr::IA32_KERNEL_GS_BASE, &gdt::TSS as *const _ as u64);

    let efer = msr::rdmsr(msr::IA32_EFER);
    msr::wrmsr(msr::IA32_EFER, efer | 1);
}

// Not a function pointer because it somehow messes up the returning
// from clone() (via clone_ret()). Not sure what the problem is.
macro_rules! with_interrupt_stack {
    (unsafe fn $wrapped:ident($stack:ident) -> usize $code:block) => {
        #[inline(never)]
        unsafe fn $wrapped(stack: *mut InterruptStack) {
            let _guard = ptrace::set_process_regs(stack);

            let is_sysemu = ptrace::breakpoint_callback(::syscall::PTRACE_SYSCALL);
            if !is_sysemu.unwrap_or(false) {
                // If not on a sysemu breakpoint
                let $stack = &mut *stack;
                $stack.scratch.rax = $code;

                if is_sysemu.is_some() {
                    // Only callback if there was a pre-syscall
                    // callback too.
                    ptrace::breakpoint_callback(::syscall::PTRACE_SYSCALL);
                }
            }
        }
    }
}

#[naked]
pub unsafe extern fn syscall_instruction() {
    with_interrupt_stack! {
        unsafe fn inner(stack) -> usize {
            let rbp;
            asm!("" : "={rbp}"(rbp) : : : "intel", "volatile");

            let scratch = &stack.scratch;
            syscall::syscall(scratch.rax, scratch.rdi, scratch.rsi, scratch.rdx, scratch.r10, scratch.r8, rbp, stack)
        }
    }

    // Yes, this is magic. No, you don't need to understand
    asm!("
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
          "
          :
          :
          :
          : "intel", "volatile");

    // Push scratch registers
    scratch_push!();
    preserved_push!();
    asm!("push fs
         mov r11, 0x18
         mov fs, r11"
         : : : : "intel", "volatile");

    // Get reference to stack variables
    let rsp: usize;
    asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

    // Map kernel
    pti::map();

    inner(rsp as *mut InterruptStack);

    // Unmap kernel
    pti::unmap();

    // Interrupt return
    asm!("pop fs" : : : : "intel", "volatile");
    preserved_pop!();
    scratch_pop!();
    asm!("iretq" : : : : "intel", "volatile");
}

#[naked]
pub unsafe extern fn syscall() {
    with_interrupt_stack! {
        unsafe fn inner(stack) -> usize {
            let rbp;
            asm!("" : "={rbp}"(rbp) : : : "intel", "volatile");

            let scratch = &stack.scratch;
            syscall::syscall(scratch.rax, stack.preserved.rbx, scratch.rcx, scratch.rdx, scratch.rsi, scratch.rdi, rbp, stack)
        }
    }

    // Push scratch registers
    scratch_push!();
    preserved_push!();
    asm!("push fs
         mov r11, 0x18
         mov fs, r11"
         : : : : "intel", "volatile");

    // Get reference to stack variables
    let rsp: usize;
    asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

    // Map kernel
    pti::map();

    inner(rsp as *mut InterruptStack);

    // Unmap kernel
    pti::unmap();

    // Interrupt return
    asm!("pop fs" : : : : "intel", "volatile");
    preserved_pop!();
    scratch_pop!();
    asm!("iretq" : : : : "intel", "volatile");
}

#[naked]
pub unsafe extern "C" fn clone_ret() {
    // The C x86_64 ABI specifies that rbp is pushed to save the old
    // call frame. Popping rbp means we're using the parent's call
    // frame and thus will not only return from this function but also
    // from the function above this one.
    // When this is called, the stack should have been
    // interrupt->inner->syscall->clone
    // then changed to
    // interrupt->inner->clone_ret->clone
    // so this will return from "inner".

    asm!("pop rbp" : : : : "intel", "volatile");
}
