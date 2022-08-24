use alloc::sync::Arc;
use core::arch::asm;
use core::mem;
use core::sync::atomic::{AtomicBool, Ordering};
use memoffset::offset_of;
use spin::Once;

use crate::{push_scratch, pop_scratch};
use crate::interrupt::handler::ScratchRegisters;
use crate::device::cpu::registers::{control_regs, tlb};
use crate::paging::{RmmA, RmmArch, TableKind};
use crate::syscall::FloatRegisters;

/// This must be used by the kernel to ensure that context switches are done atomically
/// Compare and exchange this to true when beginning a context switch on any CPU
/// The `Context::switch_to` function will set it back to false, allowing other CPU's to switch
/// This must be done, as no locks can be held on the stack during switch
pub static CONTEXT_SWITCH_LOCK: AtomicBool = AtomicBool::new(false);

//TODO: find out ideal size
pub const KFX_SIZE: usize = 512;
pub const KFX_ALIGN: usize = 16;

#[derive(Clone, Debug)]
pub struct Context {
    elr_el1: usize,
    sp_el0: usize,
    tpidr_el0: usize,   /* Pointer to TLS region for this Context               */
    tpidrro_el0: usize, /* Pointer to TLS (read-only) region for this Context   */
    spsr_el1: usize,
    esr_el1: usize,
    fx_loadable: bool,
    fx_address: usize,
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

impl Context {
    pub fn new() -> Context {
        Context {
            elr_el1: 0,
            sp_el0: 0,
            tpidr_el0: 0,
            tpidrro_el0: 0,
            spsr_el1: 0,
            esr_el1: 0,
            fx_loadable: false,
            fx_address: 0,
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
        let lr = self.lr.clone();
        self.push_stack(lr);
        self.push_stack(sig as usize);
        self.push_stack(handler as usize);
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

    pub fn get_fx_regs(&self) -> Option<FloatRegisters> {
        if !self.fx_loadable {
            return None;
        }
        let mut regs = unsafe { *(self.fx_address as *const FloatRegisters) };
        let mut new_st = regs.fp_simd_regs;
        regs.fp_simd_regs = new_st;
        Some(regs)
    }

    pub fn set_fx_regs(&mut self, mut new: FloatRegisters) -> bool {
        if !self.fx_loadable {
            return false;
        }

        {
            let old = unsafe { &*(self.fx_address as *const FloatRegisters) };
            let old_st = new.fp_simd_regs;
            let mut new_st = new.fp_simd_regs;
            for (new_st, old_st) in new_st.iter_mut().zip(&old_st) {
                *new_st = *old_st;
            }
            new.fp_simd_regs = new_st;

            // Make sure we don't use `old` from now on
        }

        unsafe {
            *(self.fx_address as *mut FloatRegisters) = new;
        }
        true
    }

    pub fn set_fx(&mut self, address: usize) {
        self.fx_address = address;
    }


    pub fn dump(&self) {
        println!("elr_el1: 0x{:016x}", self.elr_el1);
        println!("sp_el0: 0x{:016x}", self.sp_el0);
        println!("tpidr_el0: 0x{:016x}", self.tpidr_el0);
        println!("tpidrro_el0: 0x{:016x}", self.tpidrro_el0);
        println!("spsr_el1: 0x{:016x}", self.spsr_el1);
        println!("esr_el1: 0x{:016x}", self.esr_el1);
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
}

impl super::Context {
    pub fn get_fx_regs(&self) -> FloatRegisters {
        self.arch.get_fx_regs().expect("TODO: make get_fx_regs always valid")
    }

    pub fn set_fx_regs(&mut self, mut new: FloatRegisters) {
        assert!(self.arch.set_fx_regs(new), "TODO: make set_fx_regs always valid")
    }
}

pub static EMPTY_CR3: Once<rmm::PhysicalAddress> = Once::new();

// SAFETY: EMPTY_CR3 must be initialized.
pub unsafe fn empty_cr3() -> rmm::PhysicalAddress {
    debug_assert!(EMPTY_CR3.poll().is_some());
    *EMPTY_CR3.get_unchecked()
}

pub unsafe fn switch_to(prev: &mut super::Context, next: &mut super::Context) {
    let mut float_regs = &mut *(prev.arch.fx_address as *mut FloatRegisters);
    /*TODO: save float regs
    asm!(
        "stp q0, q1, [{0}, #16 * 0]",
        "stp q2, q3, [{0}, #16 * 2]",
        "stp q4, q5, [{0}, #16 * 4]",
        "stp q6, q7, [{0}, #16 * 6]",
        "stp q8, q9, [{0}, #16 * 8]",
        "stp q10, q11, [{0}, #16 * 10]",
        "stp q12, q13, [{0}, #16 * 12]",
        "stp q14, q15, [{0}, #16 * 14]",
        "stp q16, q17, [{0}, #16 * 16]",
        "stp q18, q19, [{0}, #16 * 18]",
        "stp q20, q21, [{0}, #16 * 20]",
        "stp q22, q23, [{0}, #16 * 22]",
        "stp q24, q25, [{0}, #16 * 24]",
        "stp q26, q27, [{0}, #16 * 26]",
        "stp q28, q29, [{0}, #16 * 28]",
        "stp q30, q31, [{0}, #16 * 30]",
        "mrs {1}, fpcr",
        "mrs {2}, fpsr",
        in(reg) &mut float_regs.fp_simd_regs,
        out(reg) float_regs.fpcr,
        out(reg) float_regs.fpsr
    );
    */

    prev.arch.fx_loadable = true;

    if next.arch.fx_loadable {
        let mut float_regs = &mut *(next.arch.fx_address as *mut FloatRegisters);
        /*TODO: restore float registers
        asm!(
            "ldp q0, q1, [{0}, #16 * 0]",
            "ldp q2, q3, [{0}, #16 * 2]",
            "ldp q4, q5, [{0}, #16 * 4]",
            "ldp q6, q7, [{0}, #16 * 6]",
            "ldp q8, q9, [{0}, #16 * 8]",
            "ldp q10, q11, [{0}, #16 * 10]",
            "ldp q12, q13, [{0}, #16 * 12]",
            "ldp q14, q15, [{0}, #16 * 14]",
            "ldp q16, q17, [{0}, #16 * 16]",
            "ldp q18, q19, [{0}, #16 * 18]",
            "ldp q20, q21, [{0}, #16 * 20]",
            "ldp q22, q23, [{0}, #16 * 22]",
            "ldp q24, q25, [{0}, #16 * 24]",
            "ldp q26, q27, [{0}, #16 * 26]",
            "ldp q28, q29, [{0}, #16 * 28]",
            "ldp q30, q31, [{0}, #16 * 30]",
            "msr fpcr, {1}",
            "msr fpsr, {2}",
            in(reg) &mut float_regs.fp_simd_regs,
            in(reg) float_regs.fpcr,
            in(reg) float_regs.fpsr
        );
        */
    }

    match next.addr_space {
        // Since Arc is essentially just wraps a pointer, in this case a regular pointer (as
        // opposed to dyn or slice fat pointers), and NonNull optimization exists, map_or will
        // hopefully be optimized down to checking prev and next pointers, as next cannot be null.
        Some(ref next_space) => if prev.addr_space.as_ref().map_or(true, |prev_space| !Arc::ptr_eq(&prev_space, &next_space)) {
            // Suppose we have two sibling threads A and B. A runs on CPU 0 and B on CPU 1. A
            // recently called yield and is now here about to switch back. Meanwhile, B is
            // currently creating a new mapping in their shared address space, for example a
            // message on a channel.
            //
            // Unless we acquire this lock, it may be possible that the TLB will not contain new
            // entries. While this can be caught and corrected in a page fault handler, this is not
            // true when entries are removed from a page table!
            next_space.read().table.utable.make_current();
        }
        None => {
            RmmA::set_table(TableKind::User, empty_cr3());
        }
    }

    switch_to_inner(&mut prev.arch, &mut next.arch)
}

#[naked]
unsafe extern "C" fn switch_to_inner(_prev: &mut Context, _next: &mut Context) {
    core::arch::asm!(
        "
        str x8, [x0, #{off_x8}]
        ldr x8, [x1, #{off_x8}]

        str x9, [x0, #{off_x9}]
        ldr x9, [x1, #{off_x9}]

        str x10, [x0, #{off_x10}]
        ldr x10, [x1, #{off_x10}]

        str x11, [x0, #{off_x11}]
        ldr x11, [x1, #{off_x11}]

        str x12, [x0, #{off_x12}]
        ldr x12, [x1, #{off_x12}]

        str x13, [x0, #{off_x13}]
        ldr x13, [x1, #{off_x13}]

        str x14, [x0, #{off_x14}]
        ldr x14, [x1, #{off_x14}]

        str x15, [x0, #{off_x15}]
        ldr x15, [x1, #{off_x15}]

        str x16, [x0, #{off_x16}]
        ldr x16, [x1, #{off_x16}]

        str x17, [x0, #{off_x17}]
        ldr x17, [x1, #{off_x17}]

        str x18, [x0, #{off_x18}]
        ldr x18, [x1, #{off_x18}]

        str x19, [x0, #{off_x19}]
        ldr x19, [x1, #{off_x19}]

        str x20, [x0, #{off_x20}]
        ldr x20, [x1, #{off_x20}]

        str x21, [x0, #{off_x21}]
        ldr x21, [x1, #{off_x21}]

        str x22, [x0, #{off_x22}]
        ldr x22, [x1, #{off_x22}]

        str x23, [x0, #{off_x23}]
        ldr x23, [x1, #{off_x23}]

        str x24, [x0, #{off_x24}]
        ldr x24, [x1, #{off_x24}]

        str x25, [x0, #{off_x25}]
        ldr x25, [x1, #{off_x25}]

        str x26, [x0, #{off_x26}]
        ldr x26, [x1, #{off_x26}]

        str x27, [x0, #{off_x27}]
        ldr x27, [x1, #{off_x27}]

        str x28, [x0, #{off_x28}]
        ldr x28, [x1, #{off_x28}]

        str x29, [x0, #{off_x29}]
        ldr x29, [x1, #{off_x29}]

        str x30, [x0, #{off_x30}]
        ldr x30, [x1, #{off_x30}]

        mrs x2, elr_el1
        str x2, [x0, #{off_elr_el1}]
        ldr x2, [x1, #{off_elr_el1}]
        msr elr_el1, x2

        mrs x2, sp_el0
        str x2, [x0, #{off_sp_el0}]
        ldr x2, [x1, #{off_sp_el0}]
        msr sp_el0, x2

        mrs x2, tpidr_el0
        str x2, [x0, #{off_tpidr_el0}]
        ldr x2, [x1, #{off_tpidr_el0}]
        msr tpidr_el0, x2

        mrs x2, tpidrro_el0
        str x2, [x0, #{off_tpidrro_el0}]
        ldr x2, [x1, #{off_tpidrro_el0}]
        msr tpidrro_el0, x2

        mrs x2, spsr_el1
        str x2, [x0, #{off_spsr_el1}]
        ldr x2, [x1, #{off_spsr_el1}]
        msr spsr_el1, x2

        mrs x2, esr_el1
        str x2, [x0, #{off_esr_el1}]
        ldr x2, [x1, #{off_esr_el1}]
        msr esr_el1, x2

        mov x2, sp
        str x2, [x0, #{off_sp}]
        ldr x2, [x1, #{off_sp}]
        mov sp, x2

        b {switch_hook}
        ",
        off_x8 = const(offset_of!(Context, x8)),
        off_x9 = const(offset_of!(Context, x9)),
        off_x10 = const(offset_of!(Context, x10)),
        off_x11 = const(offset_of!(Context, x11)),
        off_x12 = const(offset_of!(Context, x12)),
        off_x13 = const(offset_of!(Context, x13)),
        off_x14 = const(offset_of!(Context, x14)),
        off_x15 = const(offset_of!(Context, x15)),
        off_x16 = const(offset_of!(Context, x16)),
        off_x17 = const(offset_of!(Context, x17)),
        off_x18 = const(offset_of!(Context, x18)),
        off_x19 = const(offset_of!(Context, x19)),
        off_x20 = const(offset_of!(Context, x20)),
        off_x21 = const(offset_of!(Context, x21)),
        off_x22 = const(offset_of!(Context, x22)),
        off_x23 = const(offset_of!(Context, x23)),
        off_x24 = const(offset_of!(Context, x24)),
        off_x25 = const(offset_of!(Context, x25)),
        off_x26 = const(offset_of!(Context, x26)),
        off_x27 = const(offset_of!(Context, x27)),
        off_x28 = const(offset_of!(Context, x28)),
        off_x29 = const(offset_of!(Context, fp)),
        off_x30 = const(offset_of!(Context, lr)),
        off_elr_el1 = const(offset_of!(Context, elr_el1)),
        off_sp_el0 = const(offset_of!(Context, sp_el0)),
        off_tpidr_el0 = const(offset_of!(Context, tpidr_el0)),
        off_tpidrro_el0 = const(offset_of!(Context, tpidrro_el0)),
        off_spsr_el1 = const(offset_of!(Context, spsr_el1)),
        off_esr_el1 = const(offset_of!(Context, esr_el1)),
        off_sp = const(offset_of!(Context, sp)),

        switch_hook = sym crate::context::switch_finish_hook,
        options(noreturn),
    );
}

#[allow(dead_code)]
#[repr(packed)]
pub struct SignalHandlerStack {
    scratch: ScratchRegisters,
    padding: usize,
    handler: extern fn(usize),
    sig: usize,
    lr: usize,
}

#[naked]
unsafe extern fn signal_handler_wrapper() {
    #[inline(never)]
    unsafe extern "C" fn inner(stack: &SignalHandlerStack) {
        (stack.handler)(stack.sig);
    }

    // Push scratch registers
    core::arch::asm!(
        concat!(
            "sub sp, sp, 8",
            push_scratch!(),
            "
            mov x0, sp
            bl {inner}
            ",
            pop_scratch!(),
            "
            add sp, sp, 24
            ldr x30, [sp], #8
            ret
            "
        ),
        inner = sym inner,
        options(noreturn),
    );
}
