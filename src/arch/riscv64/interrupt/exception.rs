use core::{arch::global_asm, sync::atomic::Ordering};
use log::{error, info};
use rmm::VirtualAddress;

use crate::{
    arch::{device::irqchip, start::BOOT_HART_ID},
    memory::GenericPfFlags,
    panic::stack_trace,
    ptrace, syscall,
    syscall::flag::*,
};

const BREAKPOINT: usize = 3;
const USERMODE_ECALL: usize = 8;
const INSTRUCTION_PAGE_FAULT: usize = 12;
const LOAD_PAGE_FAULT: usize = 13;
const STORE_PAGE_FAULT: usize = 15;

use super::InterruptStack;

global_asm!(concat!(
    ".global exception_handler\n",
    ".p2align 3\n",
"exception_handler:\n",
    "csrrw tp, sscratch, tp\n",
    "beq   tp, x0, 3f\n", // exception before percpu data is available; got to be S mode

    "sd    t0, 0(tp)\n",
    "csrr  t0, sstatus\n",
    "andi  t0, t0, 1<<8\n",// SPP bit
    "bne   t0, x0, 2f\n",

    // trap/interrupt from U mode, switch stacks
    "ld      t0, 0(tp)\n",
    "sd      sp, 0(tp)\n",
    "ld      sp, 8(tp)\n",

    push_registers!(),
    "ld      t0, 0(tp)\n",
    "sd      t0, (1 * 8)(sp)\n", // save original SP
    "csrrw   t0, sscratch, tp\n",
    "sd      t0, (3 * 8)(sp)\n", // save original TP, and restore sscratch to handle double faults

    "mv      a0, sp\n",
    "jal     {0}\n",

    // save S mode stack to percpu
    "addi    t0, sp, 32 * 8\n",
    "sd      t0, 8(tp)\n",
    "li      t0, 1 << 8\n", // return to U mode (sstatus might've been modified by nested trap or context switch)
    "csrc    sstatus, t0\n",
    "j       4f\n",

"2:  ld      t0, 0(tp)\n", // S-mode
"3:\n",                    // S mode early

    "addi    sp, sp, -2 * 8\n", // fake stack frame for the stack tracer

    push_registers!(),

    "addi    t1, sp, 34 * 8\n",
    "sd      t1, (1 * 8)(sp)\n", // save original SP
    "csrrw   t1, sscratch, tp\n",
    "sd      t1, (3 * 8)(sp)\n", // save original TP, and restore sscratch to handle double faults

    "sd      t0, (33 * 8)(sp)\n",  // fill the stack frame. t0 holds original pc after push_registers
    "sd      fp, (32 * 8)(sp)\n",
    "addi    fp, sp, 34 * 8\n",

    "mv      a0, sp\n",
    "jal     {0}\n",
    // return to S mode with interrupts disabled
    // (sstatus might've been modified by nested trap or context switch)
    "li      t0, 1 << 8\n",
    "csrs   sstatus, t0\n",
    "li      t0, 1 << 5\n",
    "csrc   sstatus, t0\n",

"4:",
    pop_registers!(),
    "sret",
),
    sym exception_handler_inner
);

unsafe fn exception_handler_inner(regs: &mut InterruptStack) {
    let scause: usize;
    let sstatus: usize;
    core::arch::asm!(
        "csrr t0, scause",
        "csrr t1, sstatus",
        lateout("t0") scause,
        lateout("t1") sstatus,
        options(nostack)
    );

    //log::info!("Exception handler incoming: sepc={:x} scause={:x} sstatus={:x}", regs.iret.sepc, scause, sstatus);

    let user_mode = sstatus & (1 << 8) == 0;

    if (scause as isize) < 0 {
        handle_interrupt(scause & 0xF);
    } else if page_fault(scause, regs, user_mode) {
    } else if user_mode {
        handle_user_exception(scause, regs);
    } else {
        handle_system_exception(scause, regs);
    }
    //log::info!("Exception handler outgoing");
}

unsafe fn handle_system_exception(scause: usize, regs: &InterruptStack) {
    let stval: usize;
    let tp: usize;
    core::arch::asm!(
        "csrr t0, stval",
        "mv t1, tp",
        lateout("t0") stval,
        lateout("t1") tp,
        options(nostack)
    );

    error!(
        "S-mode exception! scause={:#016x}, stval={:#016x}",
        scause, stval
    );
    regs.dump();

    if tp == 0 {
        // Early failure - before misc::init and potentially before RMM init
        // Do not attempt to trace stack because it would probably trap again
        loop {}
    }

    stack_trace();
    loop {}
}

unsafe fn handle_interrupt(interrupt: usize) {
    // FIXME retrieve from percpu area
    // For now all the interrupts go to boot hart so this suffices...
    let hart: usize = BOOT_HART_ID.load(Ordering::Relaxed);
    irqchip::hlic::interrupt(hart, interrupt);
}

unsafe fn handle_user_exception(scause: usize, regs: &mut InterruptStack) {
    if scause == USERMODE_ECALL {
        let r = &mut regs.registers;
        regs.iret.sepc += 4; // skip ecall
        let ret = syscall::syscall(r.x17, r.x10, r.x11, r.x12, r.x13, r.x14);
        r.x10 = ret;
        return;
    }

    if scause == BREAKPOINT {
        if ptrace::breakpoint_callback(PTRACE_STOP_BREAKPOINT, None).is_some() {
            return;
        }
    }

    let stval: usize;
    core::arch::asm!(
    "csrr t0, stval",
    lateout("t0") stval,
    options(nostack)
    );

    info!(
        "U-mode exception! scause={:#016x}, stval={:#016x}",
        scause, stval
    );
    regs.dump();

    let signal = match scause {
        0 | 4 | 6 | 18 | 19 => SIGBUS, // misaligned / machine check
        2 | 8 | 9 => SIGILL,           // Illegal instruction / breakpoint / ecall
        BREAKPOINT => SIGTRAP,
        _ => SIGSEGV,
    };
    crate::ksignal(signal);
}

unsafe fn page_fault(scause: usize, regs: &mut InterruptStack, user_mode: bool) -> bool {
    if scause != INSTRUCTION_PAGE_FAULT && scause != LOAD_PAGE_FAULT && scause != STORE_PAGE_FAULT {
        return false;
    }

    let stval: usize;
    core::arch::asm!(
        "csrr t0, stval",
        lateout("t0") stval,
        options(nostack)
    );

    let address = VirtualAddress::new(stval);
    let mut generic_flags = GenericPfFlags::empty();

    generic_flags.set(GenericPfFlags::INVOLVED_WRITE, scause == STORE_PAGE_FAULT);
    generic_flags.set(GenericPfFlags::USER_NOT_SUPERVISOR, user_mode);
    generic_flags.set(
        GenericPfFlags::INSTR_NOT_DATA,
        scause == INSTRUCTION_PAGE_FAULT,
    );
    // FIXME can these conditions be distinguished? Should they be?
    generic_flags.set(GenericPfFlags::INVL, false);
    generic_flags.set(GenericPfFlags::PRESENT, false);

    crate::memory::page_fault_handler(regs, generic_flags, address).is_ok()
}
