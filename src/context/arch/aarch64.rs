use core::mem;
use core::sync::atomic::{AtomicBool, AtomicUsize, ATOMIC_BOOL_INIT, ATOMIC_USIZE_INIT, Ordering};

use crate::device::cpu::registers::{control_regs, tlb};

/// This must be used by the kernel to ensure that context switches are done atomically
/// Compare and exchange this to true when beginning a context switch on any CPU
/// The `Context::switch_to` function will set it back to false, allowing other CPU's to switch
/// This must be done, as no locks can be held on the stack during switch
pub static CONTEXT_SWITCH_LOCK: AtomicBool = ATOMIC_BOOL_INIT;

#[derive(Clone, Debug)]
pub struct Context {
    elr_el1: usize,
    sp_el0: usize,
    ttbr0_el1: usize,   /* Pointer to U4 translation table for this Context     */
    ttbr1_el1: usize,   /* Pointer to P4 translation table for this Context     */
    tpidr_el0: usize,   /* Pointer to TLS region for this Context               */
    tpidrro_el0: usize, /* Pointer to TLS (read-only) region for this Context   */
    rflags: usize,
    esr_el1: usize,
    padding: usize,
    sp: usize,          /* Stack Pointer (x31)                                  */
    lr: usize,          /* Link Register (x30)                                  */
    fp: usize,          /* Frame pointer Register (x29)                         */
    x28: usize,         /* Callee saved Register                                */
    x27: usize,         /* Callee saved Register                                */
    x26: usize,         /* Callee saved Register                                */
    x25: usize,         /* Callee saved Register                                */
    x24: usize,         /* Callee saved Register                                */
    x23: usize,         /* Callee saved Register                                */
    x22: usize,         /* Callee saved Register                                */
    x21: usize,         /* Callee saved Register                                */
    x20: usize,         /* Callee saved Register                                */
    x19: usize,         /* Callee saved Register                                */
    x18: usize,
    x17: usize,
    x16: usize,
    x15: usize,         /* Temporary Register                                   */
    x14: usize,         /* Temporary Register                                   */
    x13: usize,         /* Temporary Register                                   */
    x12: usize,         /* Temporary Register                                   */
    x11: usize,         /* Temporary Register                                   */
    x10: usize,         /* Temporary Register                                   */
    x9: usize,          /* Temporary Register                                   */
    x8: usize,          /* Indirect location Register                           */
}

static CONTEXT_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

impl Context {
    pub fn new() -> Context {
        Context {
            elr_el1: 0,
            sp_el0: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            tpidr_el0: 0,
            tpidrro_el0: 0,
            rflags: 0,          /* spsr_el1 */
            esr_el1: 0,
            padding: 0xbeef0000 | CONTEXT_COUNT.fetch_add(1, Ordering::SeqCst),
            sp: 0,
            lr: 0,
            fp: 0,
            x28: 0,
            x27: 0,
            x26: 0,
            x25: 0,
            x24: 0,
            x23: 0,
            x22: 0,
            x21: 0,
            x20: 0,
            x19: 0,
            x18: 0,
            x17: 0,
            x16: 0,
            x15: 0,
            x14: 0,
            x13: 0,
            x12: 0,
            x11: 0,
            x10: 0,
            x9: 0,
            x8: 0,
        }
    }

    pub fn get_page_utable(&self) -> usize {
        self.ttbr0_el1
    }

    pub fn get_page_ktable(&self) -> usize {
        self.ttbr1_el1
    }

    pub fn set_fx(&mut self, _address: usize) {
    }

    pub fn set_page_utable(&mut self, address: usize) {
        self.ttbr0_el1 = address;
    }

    pub fn set_page_ktable(&mut self, address: usize) {
        self.ttbr1_el1 = address;
    }

    pub fn set_stack(&mut self, address: usize) {
        self.sp = address;
    }

    pub fn set_lr(&mut self, address: usize) {
        self.lr = address;
    }

    pub fn set_tcb(&mut self, pid: usize) {
        self.tpidr_el0 = (crate::USER_TCB_OFFSET + pid * crate::PAGE_SIZE);
    }

    pub fn set_fp(&mut self, address: usize) {
        self.fp = address;
    }

    pub fn set_context_handle(&mut self) {
        let address = self as *const _ as usize;
        self.tpidrro_el0 = address;
    }

    pub fn get_context_handle(&mut self) -> usize {
        self.tpidrro_el0
    }

    pub unsafe fn signal_stack(&mut self, handler: extern fn(usize), sig: u8) {
        self.push_stack(sig as usize);
        self.push_stack(handler as usize);
        let lr = self.lr.clone();
        self.push_stack(lr);
        self.set_lr(signal_handler_wrapper as usize);
    }

    pub unsafe fn push_stack(&mut self, value: usize) {
        self.sp -= 1 * mem::size_of::<usize>();
        *(self.sp as *mut usize) = value;
    }

    pub unsafe fn pop_stack(&mut self) -> usize {
        let value = *(self.sp as *const usize);
        self.sp += 1 * mem::size_of::<usize>();
        value
    }

    pub fn dump(&self) {
        println!("elr_el1: 0x{:016x}", self.elr_el1);
        println!("sp_el0: 0x{:016x}", self.sp_el0);
        println!("ttbr0_el1: 0x{:016x}", self.ttbr0_el1);
        println!("ttbr1_el1: 0x{:016x}", self.ttbr1_el1);
        println!("tpidr_el0: 0x{:016x}", self.tpidr_el0);
        println!("tpidrro_el0: 0x{:016x}", self.tpidrro_el0);
        println!("rflags: 0x{:016x}", self.rflags);
        println!("esr_el1: 0x{:016x}", self.esr_el1);
        println!("padding: 0x{:016x}", self.padding);
        println!("sp: 0x{:016x}", self.sp);
        println!("lr: 0x{:016x}", self.lr);
        println!("fp: 0x{:016x}", self.fp);
        println!("x28: 0x{:016x}", self.x28);
        println!("x27: 0x{:016x}", self.x27);
        println!("x26: 0x{:016x}", self.x26);
        println!("x25: 0x{:016x}", self.x25);
        println!("x24: 0x{:016x}", self.x24);
        println!("x23: 0x{:016x}", self.x23);
        println!("x22: 0x{:016x}", self.x22);
        println!("x21: 0x{:016x}", self.x21);
        println!("x20: 0x{:016x}", self.x20);
        println!("x19: 0x{:016x}", self.x19);
        println!("x18: 0x{:016x}", self.x18);
        println!("x17: 0x{:016x}", self.x17);
        println!("x16: 0x{:016x}", self.x16);
        println!("x15: 0x{:016x}", self.x15);
        println!("x14: 0x{:016x}", self.x14);
        println!("x13: 0x{:016x}", self.x13);
        println!("x12: 0x{:016x}", self.x12);
        println!("x11: 0x{:016x}", self.x11);
        println!("x10: 0x{:016x}", self.x10);
        println!("x9: 0x{:016x}", self.x9);
        println!("x8: 0x{:016x}", self.x8);
    }

    #[cold]
    #[inline(never)]
    #[naked]
    pub unsafe fn switch_to(&mut self, next: &mut Context) {
        self.ttbr0_el1 = control_regs::ttbr0_el1() as usize;
        if next.ttbr0_el1 != self.ttbr0_el1 {
            control_regs::ttbr0_el1_write(next.ttbr0_el1 as u64);
            tlb::flush_all();
        }

        llvm_asm!("mov   $0, x8" : "=r"(self.x8) : : "memory" : "volatile");
        llvm_asm!("mov   x8, $0" : :  "r"(next.x8) :"memory" : "volatile");

        llvm_asm!("mov   $0, x9" : "=r"(self.x9) : : "memory" : "volatile");
        llvm_asm!("mov   x9, $0" : :  "r"(next.x9) :"memory" : "volatile");

        llvm_asm!("mov   $0, x10" : "=r"(self.x10) : : "memory" : "volatile");
        llvm_asm!("mov   x10, $0" : :  "r"(next.x10) :"memory" : "volatile");

        llvm_asm!("mov   $0, x11" : "=r"(self.x11) : : "memory" : "volatile");
        llvm_asm!("mov   x11, $0" : :  "r"(next.x11) :"memory" : "volatile");

        llvm_asm!("mov   $0, x12" : "=r"(self.x12) : : "memory" : "volatile");
        llvm_asm!("mov   x12, $0" : :  "r"(next.x12) :"memory" : "volatile");

        llvm_asm!("mov   $0, x13" : "=r"(self.x13) : : "memory" : "volatile");
        llvm_asm!("mov   x13, $0" : :  "r"(next.x13) :"memory" : "volatile");

        llvm_asm!("mov   $0, x14" : "=r"(self.x14) : : "memory" : "volatile");
        llvm_asm!("mov   x14, $0" : :  "r"(next.x14) :"memory" : "volatile");

        llvm_asm!("mov   $0, x15" : "=r"(self.x15) : : "memory" : "volatile");
        llvm_asm!("mov   x15, $0" : :  "r"(next.x15) :"memory" : "volatile");

        llvm_asm!("mov   $0, x16" : "=r"(self.x16) : : "memory" : "volatile");
        llvm_asm!("mov   x16, $0" : :  "r"(next.x16) :"memory" : "volatile");

        llvm_asm!("mov   $0, x17" : "=r"(self.x17) : : "memory" : "volatile");
        llvm_asm!("mov   x17, $0" : :  "r"(next.x17) :"memory" : "volatile");

        llvm_asm!("mov   $0, x18" : "=r"(self.x18) : : "memory" : "volatile");
        llvm_asm!("mov   x18, $0" : :  "r"(next.x18) :"memory" : "volatile");

        llvm_asm!("mov   $0, x19" : "=r"(self.x19) : : "memory" : "volatile");
        llvm_asm!("mov   x19, $0" : :  "r"(next.x19) :"memory" : "volatile");

        llvm_asm!("mov   $0, x20" : "=r"(self.x20) : : "memory" : "volatile");
        llvm_asm!("mov   x20, $0" : :  "r"(next.x20) :"memory" : "volatile");

        llvm_asm!("mov   $0, x21" : "=r"(self.x21) : : "memory" : "volatile");
        llvm_asm!("mov   x21, $0" : :  "r"(next.x21) :"memory" : "volatile");

        llvm_asm!("mov   $0, x22" : "=r"(self.x22) : : "memory" : "volatile");
        llvm_asm!("mov   x22, $0" : :  "r"(next.x22) :"memory" : "volatile");

        llvm_asm!("mov   $0, x23" : "=r"(self.x23) : : "memory" : "volatile");
        llvm_asm!("mov   x23, $0" : :  "r"(next.x23) :"memory" : "volatile");

        llvm_asm!("mov   $0, x24" : "=r"(self.x24) : : "memory" : "volatile");
        llvm_asm!("mov   x24, $0" : :  "r"(next.x24) :"memory" : "volatile");

        llvm_asm!("mov   $0, x25" : "=r"(self.x25) : : "memory" : "volatile");
        llvm_asm!("mov   x25, $0" : :  "r"(next.x25) :"memory" : "volatile");

        llvm_asm!("mov   $0, x26" : "=r"(self.x26) : : "memory" : "volatile");
        llvm_asm!("mov   x26, $0" : :  "r"(next.x26) :"memory" : "volatile");

        llvm_asm!("mov   $0, x27" : "=r"(self.x27) : : "memory" : "volatile");
        llvm_asm!("mov   x27, $0" : :  "r"(next.x27) :"memory" : "volatile");

        llvm_asm!("mov   $0, x28" : "=r"(self.x28) : : "memory" : "volatile");
        llvm_asm!("mov   x28, $0" : :  "r"(next.x28) :"memory" : "volatile");

        llvm_asm!("mov   $0, x29" : "=r"(self.fp) : : "memory" : "volatile");
        llvm_asm!("mov   x29, $0" : :  "r"(next.fp) :"memory" : "volatile");

        llvm_asm!("mov   $0, x30" : "=r"(self.lr) : : "memory" : "volatile");
        llvm_asm!("mov   x30, $0" : :  "r"(next.lr) :"memory" : "volatile");

        llvm_asm!("mrs   $0, elr_el1" : "=r"(self.elr_el1) : : "memory" : "volatile");
        llvm_asm!("msr   elr_el1, $0" : : "r"(next.elr_el1) : "memory" : "volatile");

        llvm_asm!("mrs   $0, sp_el0" : "=r"(self.sp_el0) : : "memory" : "volatile");
        llvm_asm!("msr   sp_el0, $0" : : "r"(next.sp_el0) : "memory" : "volatile");

        llvm_asm!("mrs   $0, tpidr_el0" : "=r"(self.tpidr_el0) : : "memory" : "volatile");
        llvm_asm!("msr   tpidr_el0, $0" : : "r"(next.tpidr_el0) : "memory" : "volatile");

        llvm_asm!("mrs   $0, tpidrro_el0" : "=r"(self.tpidrro_el0) : : "memory" : "volatile");
        llvm_asm!("msr   tpidrro_el0, $0" : : "r"(next.tpidrro_el0) : "memory" : "volatile");

        llvm_asm!("mrs   $0, spsr_el1" : "=r"(self.rflags) : : "memory" : "volatile");
        llvm_asm!("msr   spsr_el1, $0" : : "r"(next.rflags) : "memory" : "volatile");

        llvm_asm!("mrs   $0, esr_el1" : "=r"(self.esr_el1) : : "memory" : "volatile");
        llvm_asm!("msr   esr_el1, $0" : : "r"(next.esr_el1) : "memory" : "volatile");

        llvm_asm!("mov   $0, sp" : "=r"(self.sp) : : "memory" : "volatile");
        llvm_asm!("mov   sp, $0" : : "r"(next.sp) : "memory" : "volatile");

        CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);
    }
}

#[allow(dead_code)]
#[repr(packed)]
pub struct SignalHandlerStack {
    x28: usize,         /* Callee saved Register                                */
    x27: usize,         /* Callee saved Register                                */
    x26: usize,         /* Callee saved Register                                */
    x25: usize,         /* Callee saved Register                                */
    x24: usize,         /* Callee saved Register                                */
    x23: usize,         /* Callee saved Register                                */
    x22: usize,         /* Callee saved Register                                */
    x21: usize,         /* Callee saved Register                                */
    x20: usize,         /* Callee saved Register                                */
    x19: usize,         /* Callee saved Register                                */
    x18: usize,
    x17: usize,
    x16: usize,
    x15: usize,         /* Temporary Register                                   */
    x14: usize,         /* Temporary Register                                   */
    x13: usize,         /* Temporary Register                                   */
    x12: usize,         /* Temporary Register                                   */
    x11: usize,         /* Temporary Register                                   */
    x10: usize,         /* Temporary Register                                   */
    x9: usize,          /* Temporary Register                                   */
    x8: usize,          /* Indirect location Register                           */
    x7: usize,
    x6: usize,
    x5: usize,
    x4: usize,
    x3: usize,
    x2: usize,
    x1: usize,
    x0: usize,
    lr: usize,
    handler: extern fn(usize),
    sig: usize,
}

#[naked]
unsafe extern fn signal_handler_wrapper() {
    #[inline(never)]
    unsafe fn inner(stack: &SignalHandlerStack) {
        (stack.handler)(stack.sig);
    }

    // Push scratch registers
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
          str	    x28, [sp, #-8]!"
    : : : : "volatile");

    // Get reference to stack variables
    let sp: usize;
    llvm_asm!("" : "={sp}"(sp) : : : "volatile");

    let ptr = sp as *const SignalHandlerStack;
    let final_lr = (*ptr).lr;

    // Call inner rust function
    inner(&*(sp as *const SignalHandlerStack));

    // Pop scratch registers, error code, and return
    llvm_asm!("ldr	    x28, [sp], #8
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
          ldr	    x1, [sp], #8"
    : : : : "volatile");

    llvm_asm!("mov       x30, $0" : : "r"(final_lr) : "memory" : "volatile");
}
