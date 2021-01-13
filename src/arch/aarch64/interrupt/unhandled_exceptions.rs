use crate::{
    context,
    cpu_id,
    interrupt::{self, InterruptStack, stack_trace},
};

bitflags! {
    pub struct ExceptionClasses: u32 {
        const   SVC_INSN_IN_AARCH64_STATE = 0b10101 << 26;
        const   DATA_ABORT_FROM_LOWER_EL  = 0b100100 << 26;
        const   BKPT_INSN_IN_AARCH64_STATE = 0b111100 << 26;
    }
}

#[inline(never)]
pub unsafe extern fn report_exception(stack: &InterruptStack) {
    println!("Unhandled exception");

    stack.dump();
    stack_trace();

    println!("CPU {}, PID {:?}", cpu_id(), context::context_id());
    //WARNING: name cannot be grabed, it may deadlock

    println!("HALT");
    loop {
        interrupt::halt();
    }
}

#[naked]
#[no_mangle]
pub unsafe extern fn do_report_exception() {
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
    report_exception(&*(sp as *const InterruptStack));

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
          ldr	    x0, [sp], #8"
    : : : : "volatile");

    llvm_asm!("eret" :::: "volatile");
}
