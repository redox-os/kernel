use crate::{
    arch::{interrupt::InterruptStack},
    context,
    syscall,
    syscall::flag::{PTRACE_FLAG_IGNORE, PTRACE_STOP_PRE_SYSCALL, PTRACE_STOP_POST_SYSCALL},
};

#[no_mangle]
pub unsafe extern fn do_exception_unhandled() {}

/*
#[naked]
#[no_mangle]
pub unsafe extern fn do_exception_unhandled() {
    #[inline(never)]
    unsafe fn inner(stack: &mut InterruptStack) -> usize {
        println!("do_exception_unhandled: ELR: 0x{:016x}", stack.elr_el1);
        loop {}
    }

    llvm_asm!("str	    x0, [sp, #-8]!
          str	    x1, [sp, #-8]!
          str	    x2, [sp, #-8]!
          str	    x3, [sp, #-8]!
          str	    x4, [sp, #-8]!
          str	    x5, [sp, #-8]!
          str	    x6, [sp, #-8]!
          str	    x7, [sp, #-8]!
          str	    x8, [sp, #-8]!
          str	    x9, [sp, #-8]!
          str	    x10, [sp, #-8]!
          str	    x11, [sp, #-8]!
          str	    x12, [sp, #-8]!
          str	    x13, [sp, #-8]!
          str	    x14, [sp, #-8]!
          str	    x15, [sp, #-8]!
          str	    x16, [sp, #-8]!
          str	    x17, [sp, #-8]!
          str	    x18, [sp, #-8]!
          str	    x19, [sp, #-8]!
          str	    x20, [sp, #-8]!
          str	    x21, [sp, #-8]!
          str	    x22, [sp, #-8]!
          str	    x23, [sp, #-8]!
          str	    x24, [sp, #-8]!
          str	    x25, [sp, #-8]!
          str	    x26, [sp, #-8]!
          str	    x27, [sp, #-8]!
          str	    x28, [sp, #-8]!
          str	    x29, [sp, #-8]!
          str	    x30, [sp, #-8]!

          mrs       x18, sp_el0
          str       x18, [sp, #-8]!

          mrs       x18, esr_el1
          str       x18, [sp, #-8]!

          mrs       x18, spsr_el1
          str       x18, [sp, #-8]!

          mrs       x18, tpidrro_el0
          str       x18, [sp, #-8]!

          mrs       x18, tpidr_el0
          str       x18, [sp, #-8]!

          str       x18, [sp, #-8]!

          mrs       x18, elr_el1
          str       x18, [sp, #-8]!"
    : : : : "volatile");

    let sp: usize;
    llvm_asm!("" : "={sp}"(sp) : : : "volatile");
    llvm_asm!("mov x29, sp" : : : : "volatile");

    let a = inner(&mut *(sp as *mut InterruptStack));
}
*/

#[no_mangle]
pub unsafe extern fn do_exception_synchronous() {}

/*
#[naked]
#[no_mangle]
pub unsafe extern fn do_exception_synchronous() {
    #[inline(never)]
    unsafe fn inner(stack: &mut InterruptStack) -> usize {
        let exception_code = (stack.esr_el1 & (0x3f << 26)) >> 26;
        if exception_code != 0b010101 {
            println!("do_exception_synchronous: Non-SVC!!!");
            loop {}
        } else {
            println!("do_exception_synchronous: SVC: x8: 0x{:016x}", stack.scratch.x8);
        }

        llvm_asm!("nop": : : : "volatile");
        llvm_asm!("nop": : : : "volatile");
        llvm_asm!("nop": : : : "volatile");
        llvm_asm!("nop": : : : "volatile");

        let fp;
        llvm_asm!("" : "={fp}"(fp) : : : "volatile");

        syscall::syscall(
            stack.scratch.x8,
            stack.scratch.x0,
            stack.scratch.x1,
            stack.scratch.x2,
            stack.scratch.x3,
            stack.scratch.x4,
            fp,
            stack
        )
    }

    llvm_asm!("str	    x0, [sp, #-8]!
          str	    x1, [sp, #-8]!
          str	    x2, [sp, #-8]!
          str	    x3, [sp, #-8]!
          str	    x4, [sp, #-8]!
          str	    x5, [sp, #-8]!
          str	    x6, [sp, #-8]!
          str	    x7, [sp, #-8]!
          str	    x8, [sp, #-8]!
          str	    x9, [sp, #-8]!
          str	    x10, [sp, #-8]!
          str	    x11, [sp, #-8]!
          str	    x12, [sp, #-8]!
          str	    x13, [sp, #-8]!
          str	    x14, [sp, #-8]!
          str	    x15, [sp, #-8]!
          str	    x16, [sp, #-8]!
          str	    x17, [sp, #-8]!
          str	    x18, [sp, #-8]!
          str	    x19, [sp, #-8]!
          str	    x20, [sp, #-8]!
          str	    x21, [sp, #-8]!
          str	    x22, [sp, #-8]!
          str	    x23, [sp, #-8]!
          str	    x24, [sp, #-8]!
          str	    x25, [sp, #-8]!
          str	    x26, [sp, #-8]!
          str	    x27, [sp, #-8]!
          str	    x28, [sp, #-8]!
          str	    x29, [sp, #-8]!
          str	    x30, [sp, #-8]!

          mrs       x18, sp_el0
          str       x18, [sp, #-8]!

          mrs       x18, esr_el1
          str       x18, [sp, #-8]!

          mrs       x18, spsr_el1
          str       x18, [sp, #-8]!

          mrs       x18, tpidrro_el0
          str       x18, [sp, #-8]!

          mrs       x18, tpidr_el0
          str       x18, [sp, #-8]!

          str       x18, [sp, #-8]!

          mrs       x18, elr_el1
          str       x18, [sp, #-8]!"
    : : : : "volatile");

    let sp: usize;
    llvm_asm!("" : "={sp}"(sp) : : : "volatile");
    llvm_asm!("mov x29, sp" : : : : "volatile");

    let a = inner(&mut *(sp as *mut InterruptStack));

    llvm_asm!("" : : "{x0}"(a) : : "volatile");

    llvm_asm!("ldr	    x18, [sp], #8
          msr	    elr_el1, x18

          ldr	    x18, [sp], #8

          ldr	    x18, [sp], #8
          msr	    tpidr_el0, x18

          ldr	    x18, [sp], #8
          msr	    tpidrro_el0, x18

          ldr	    x18, [sp], #8
          msr	    spsr_el1, x18

          ldr	    x18, [sp], #8
          msr	    esr_el1, x18

          ldr	    x18, [sp], #8
          msr       sp_el0, x18

          ldr	    x30, [sp], #8
          ldr	    x29, [sp], #8
          ldr	    x28, [sp], #8
          ldr	    x27, [sp], #8
          ldr	    x26, [sp], #8
          ldr	    x25, [sp], #8
          ldr	    x24, [sp], #8
          ldr	    x23, [sp], #8
          ldr	    x22, [sp], #8
          ldr	    x21, [sp], #8
          ldr	    x20, [sp], #8
          ldr	    x19, [sp], #8
          ldr	    x18, [sp], #8
          ldr	    x17, [sp], #8
          ldr	    x16, [sp], #8
          ldr	    x15, [sp], #8
          ldr	    x14, [sp], #8
          ldr	    x13, [sp], #8
          ldr	    x12, [sp], #8
          ldr	    x11, [sp], #8
          ldr	    x10, [sp], #8
          ldr	    x9, [sp], #8
          ldr	    x8, [sp], #8
          ldr	    x7, [sp], #8
          ldr	    x6, [sp], #8
          ldr	    x5, [sp], #8
          ldr	    x4, [sp], #8
          ldr	    x3, [sp], #8
          ldr	    x2, [sp], #8
          ldr	    x1, [sp], #8
          add       sp, sp, #8"     /* Skip over x0 - it's got the retval of inner already */
    : : : : "volatile");

    llvm_asm!("eret" :::: "volatile");
}
*/

#[allow(dead_code)]
#[repr(packed)]
pub struct SyscallStack {
    pub elr_el1: usize,
    pub padding: usize,
    pub tpidr: usize,
    pub tpidrro: usize,
    pub rflags: usize,
    pub esr: usize,
    pub sp: usize,
    pub lr: usize,
    pub fp: usize,
    pub x28: usize,
    pub x27: usize,
    pub x26: usize,
    pub x25: usize,
    pub x24: usize,
    pub x23: usize,
    pub x22: usize,
    pub x21: usize,
    pub x20: usize,
    pub x19: usize,
    pub x18: usize,
    pub x17: usize,
    pub x16: usize,
    pub x15: usize,
    pub x14: usize,
    pub x13: usize,
    pub x12: usize,
    pub x11: usize,
    pub x10: usize,
    pub x9: usize,
    pub x8: usize,
    pub x7: usize,
    pub x6: usize,
    pub x5: usize,
    pub x4: usize,
    pub x3: usize,
    pub x2: usize,
    pub x1: usize,
    pub x0: usize,
}

#[macro_export]
macro_rules! with_exception_stack {
    (|$stack:ident| $code:block) => {{
            let $stack = &mut *$stack;
            (*$stack).scratch.x0 = $code;
    }}
}

#[no_mangle]
pub unsafe extern "C" fn __inner_syscall_instruction(stack: *mut InterruptStack) {
    with_exception_stack!(|stack| {
        // Set a restore point for clone
        let fp;
        asm!("mov {}, fp", out(reg) fp);

        let scratch = &stack.scratch;
        syscall::syscall(scratch.x8, scratch.x0, scratch.x1, scratch.x2, scratch.x3, scratch.x4, fp, stack)
    });
}

function!(syscall_instruction => {
    "
        nop
    ",

    // Push context registers
    push_preserved!(),
    push_scratch!(),
    push_special!(),

    // TODO: Map PTI

    // Call inner function
    "mov x0, sp\n",
    "bl __inner_syscall_instruction\n",

    // TODO: Unmap PTI

    // Pop context registers
    pop_special!(),
    pop_scratch!(),
    pop_preserved!(),

    // Return
    "eret\n",
});

function!(clone_ret => {
    "ldp x29, x30, [sp], #16\n",
    "mov sp, x29\n",
    "ret\n",
});
