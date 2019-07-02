use crate::arch::macros::InterruptStack;
use crate::arch::{gdt, pti};
use crate::common::unique::Unique;
use crate::{context, ptrace, syscall};
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
        /// Because of how clones work, we need a function that returns a
        /// usize. Here, `inner` will be this function. The child process in a
        /// clone will terminate this function with a 0 return value, and it
        /// might also have updated the interrupt_stack pointer.
        #[inline(never)]
        unsafe fn $wrapped(stack: *mut SyscallStack) {
            let stack = &mut *stack;
            {
                let contexts = context::contexts();
                if let Some(context) = contexts.current() {
                    let mut context = context.write();
                    if let Some(ref mut kstack) = context.kstack {
                        context.regs = Some((kstack.as_mut_ptr() as usize, Unique::new_unchecked(&mut stack.interrupt_stack)));
                    }
                }
            }

            let is_sysemu = ptrace::breakpoint_callback(false);
            if !is_sysemu.unwrap_or(false) {
                // If not on a sysemu breakpoint
                let $stack = &mut *stack;
                $stack.interrupt_stack.scratch.rax = $code;

                if is_sysemu.is_some() {
                    // Only callback if there was a pre-syscall
                    // callback too.
                    ptrace::breakpoint_callback(false);
                }
            }

            {
                let contexts = context::contexts();
                if let Some(context) = contexts.current() {
                    let mut context = context.write();
                    context.regs = None;
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

            let scratch = &stack.interrupt_stack.scratch;
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
    asm!("push fs
         mov r11, 0x18
         mov fs, r11
         push rbx"
         : : : : "intel", "volatile");

    // Get reference to stack variables
    let rsp: usize;
    asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

    // Map kernel
    pti::map();

    inner(rsp as *mut SyscallStack);

    // Unmap kernel
    pti::unmap();

    // Interrupt return
    asm!("pop rbx
         pop fs"
         : : : : "intel", "volatile");
    scratch_pop!();
    asm!("iretq" : : : : "intel", "volatile");
}

#[naked]
pub unsafe extern fn syscall() {
    with_interrupt_stack! {
        unsafe fn inner(stack) -> usize {
            let rbp;
            asm!("" : "={rbp}"(rbp) : : : "intel", "volatile");

            let scratch = &stack.interrupt_stack.scratch;
            syscall::syscall(scratch.rax, stack.rbx, scratch.rcx, scratch.rdx, scratch.rsi, scratch.rdi, rbp, stack)
        }
    }

    // Push scratch registers
    scratch_push!();
    asm!("push fs
         mov r11, 0x18
         mov fs, r11
         push rbx"
         : : : : "intel", "volatile");

    // Get reference to stack variables
    let rsp: usize;
    asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

    // Map kernel
    pti::map();

    inner(rsp as *mut SyscallStack);

    // Unmap kernel
    pti::unmap();

    // Interrupt return
    asm!("pop rbx
         pop fs"
         : : : : "intel", "volatile");
    scratch_pop!();
    asm!("iretq" : : : : "intel", "volatile");
}

#[allow(dead_code)]
#[repr(packed)]
pub struct SyscallStack {
    pub rbx: usize,
    pub interrupt_stack: InterruptStack,

    // Will only be present if syscall is called from another ring
    pub rsp: usize,
    pub ss: usize,
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
