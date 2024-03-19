use alloc::sync::Arc;
use core::{
    arch::asm,
    mem,
    mem::offset_of,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use spin::Once;

use crate::{
    device::cpu::registers::{control_regs, tlb},
    paging::{RmmA, RmmArch, TableKind},
    syscall::FloatRegisters,
    percpu::PercpuBlock,
};

/// This must be used by the kernel to ensure that context switches are done atomically
/// Compare and exchange this to true when beginning a context switch on any CPU
/// The `Context::switch_to` function will set it back to false, allowing other CPU's to switch
/// This must be done, as no locks can be held on the stack during switch
pub static CONTEXT_SWITCH_LOCK: AtomicBool = AtomicBool::new(false);

// 512 bytes for registers, extra bytes for fpcr and fpsr
pub const KFX_ALIGN: usize = 16;
pub const KSTACK_SIZE: usize = 65536;
pub const KSTACK_ALIGN: usize = 16;

#[derive(Clone, Debug)]
pub struct Context {
    elr_el1: usize,
    sp_el0: usize,
    pub(crate) tpidr_el0: usize, /* Pointer to TLS region for this Context               */
    pub(crate) tpidrro_el0: usize, /* Pointer to TLS (read-only) region for this Context   */
    spsr_el1: usize,
    esr_el1: usize,
    fx_loadable: bool,
    sp: usize,  /* Stack Pointer (x31)                                  */
    lr: usize,  /* Link Register (x30)                                  */
    fp: usize,  /* Frame pointer Register (x29)                         */
    x28: usize, /* Callee saved Register                                */
    x27: usize, /* Callee saved Register                                */
    x26: usize, /* Callee saved Register                                */
    x25: usize, /* Callee saved Register                                */
    x24: usize, /* Callee saved Register                                */
    x23: usize, /* Callee saved Register                                */
    x22: usize, /* Callee saved Register                                */
    x21: usize, /* Callee saved Register                                */
    x20: usize, /* Callee saved Register                                */
    x19: usize, /* Callee saved Register                                */
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
        }
    }

    pub fn set_stack(&mut self, address: usize) {
        self.sp = address;
    }

    pub fn set_x28(&mut self, x28: usize) {
        self.x28 = x28;
    }

    pub fn set_lr(&mut self, address: usize) {
        self.lr = address;
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
    }
}

impl super::Context {
    pub fn get_fx_regs(&self) -> FloatRegisters {
        if !self.arch.fx_loadable {
            panic!("TODO: make get_fx_regs always work");
        }

        unsafe { ptr::read(self.kfx.as_ptr() as *const FloatRegisters) }
    }

    pub fn set_fx_regs(&mut self, mut new: FloatRegisters) {
        if !self.arch.fx_loadable {
            panic!("TODO: make set_fx_regs always work");
        }

        unsafe {
            ptr::write(self.kfx.as_mut_ptr() as *mut FloatRegisters, new);
        }
    }
    pub fn current_syscall(&self) -> Option<[usize; 6]> {
        if !self.inside_syscall {
            return None;
        }
        let regs = self.regs()?;
        let scratch = &regs.scratch;
        Some([scratch.x8, scratch.x0, scratch.x1, scratch.x2, scratch.x3, scratch.x4])
    }
}

pub static EMPTY_CR3: Once<rmm::PhysicalAddress> = Once::new();

// SAFETY: EMPTY_CR3 must be initialized.
pub unsafe fn empty_cr3() -> rmm::PhysicalAddress {
    debug_assert!(EMPTY_CR3.poll().is_some());
    *EMPTY_CR3.get_unchecked()
}

pub unsafe fn switch_to(prev: &mut super::Context, next: &mut super::Context) {
    let mut float_regs = &mut *(prev.kfx.as_mut_ptr() as *mut FloatRegisters);
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
        in(reg) core::ptr::addr_of_mut!(float_regs.fp_simd_regs),
        out(reg) float_regs.fpcr,
        out(reg) float_regs.fpsr
    );

    prev.arch.fx_loadable = true;

    if next.arch.fx_loadable {
        let mut float_regs = &mut *(next.kfx.as_mut_ptr() as *mut FloatRegisters);
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
            in(reg) core::ptr::addr_of_mut!(float_regs.fp_simd_regs),
            in(reg) float_regs.fpcr,
            in(reg) float_regs.fpsr
        );
    }

    PercpuBlock::current().new_addrsp_tmp.set(next.addr_space.clone());

    switch_to_inner(&mut prev.arch, &mut next.arch)
}

#[naked]
unsafe extern "C" fn switch_to_inner(_prev: &mut Context, _next: &mut Context) {
    core::arch::asm!(
        "
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
