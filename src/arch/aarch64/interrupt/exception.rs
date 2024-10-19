use rmm::VirtualAddress;

use crate::{
    exception_stack,
    memory::{ArchIntCtx, GenericPfFlags},
    panic::stack_trace,
    syscall,
    syscall::flag::*,
};

use super::InterruptStack;

exception_stack!(synchronous_exception_at_el1_with_sp0, |stack| {
    println!("Synchronous exception at EL1 with SP0");
    stack.dump();
    stack_trace();
    loop {}
});

fn exception_code(esr: usize) -> u8 {
    ((esr >> 26) & 0x3f) as u8
}
fn iss(esr: usize) -> u32 {
    (esr & 0x01ff_ffff) as u32
}

unsafe fn far_el1() -> usize {
    let ret: usize;
    core::arch::asm!("mrs {}, far_el1", out(reg) ret);
    ret
}

unsafe fn instr_data_abort_inner(
    stack: &mut InterruptStack,
    from_user: bool,
    instr_not_data: bool,
    _from: &str,
) -> bool {
    let iss = iss(stack.iret.esr_el1);
    let fsc = iss & 0x3F;
    //dbg!(fsc);

    let was_translation_fault = fsc >= 0b000100 && fsc <= 0b000111;
    //let was_permission_fault = fsc >= 0b001101 && fsc <= 0b001111;
    let write_not_read_if_data = iss & (1 << 6) != 0;

    let mut flags = GenericPfFlags::empty();
    flags.set(GenericPfFlags::PRESENT, !was_translation_fault);

    // TODO: RMW instructions may "involve" writing to (possibly invalid) memory, but AArch64
    // doesn't appear to require that flag to be set if the read alone would trigger a fault.
    flags.set(
        GenericPfFlags::INVOLVED_WRITE,
        write_not_read_if_data && !instr_not_data,
    );
    flags.set(GenericPfFlags::INSTR_NOT_DATA, instr_not_data);
    flags.set(GenericPfFlags::USER_NOT_SUPERVISOR, from_user);

    let faulting_addr = VirtualAddress::new(far_el1());
    //dbg!(faulting_addr, flags, from);

    crate::memory::page_fault_handler(stack, flags, faulting_addr).is_ok()
}

unsafe fn cntfrq_el0() -> usize {
    let ret: usize;
    core::arch::asm!("mrs {}, cntfrq_el0", out(reg) ret);
    ret
}

unsafe fn cntpct_el0() -> usize {
    let ret: usize;
    core::arch::asm!("mrs {}, cntpct_el0", out(reg) ret);
    ret
}

unsafe fn cntvct_el0() -> usize {
    let ret: usize;
    core::arch::asm!("mrs {}, cntvct_el0", out(reg) ret);
    ret
}

unsafe fn instr_trapped_msr_mrs_inner(
    stack: &mut InterruptStack,
    _from_user: bool,
    _instr_not_data: bool,
    _from: &str,
) -> bool {
    let iss = iss(stack.iret.esr_el1);
    // let res0 = (iss & 0x1C0_0000) >> 22;
    let op0 = (iss & 0x030_0000) >> 20;
    let op2 = (iss & 0x00e_0000) >> 17;
    let op1 = (iss & 0x001_c000) >> 14;
    let crn = (iss & 0x000_3c00) >> 10;
    let rt = (iss & 0x000_03e0) >> 5;
    let crm = (iss & 0x000_001e) >> 1;
    let dir = iss & 0x000_0001;

    /*
    print!("iss=0x{:x}, res0=0b{:03b}, op0=0b{:02b}\n
            op2=0b{:03b}, op1=0b{:03b}, crn=0b{:04b}\n
            rt=0b{:05b}, crm=0b{:04b}, dir=0b{:b}\n",
            iss, res0, op0, op2, op1, crn, rt, crm, dir);
    */

    match (op0, op1, crn, crm, op2, dir) {
        //MRS <Xt>, CNTFRQ_EL0
        (0b11, 0b011, 0b1110, 0b0000, 0b000, 0b1) => {
            let reg_val = cntfrq_el0();
            stack.store_reg(rt as usize, reg_val);
            //skip faulting instruction, A64 instructions are always 32-bits
            stack.iret.elr_el1 += 4;
            return true;
        }
        //MRS <Xt>, CNTPCT_EL0
        (0b11, 0b011, 0b1110, 0b0000, 0b001, 0b1) => {
            let reg_val = cntpct_el0();
            stack.store_reg(rt as usize, reg_val);
            //skip faulting instruction, A64 instructions are always 32-bits
            stack.iret.elr_el1 += 4;
            return true;
        }
        //MRS <Xt>, CNTVCT_EL0
        (0b11, 0b011, 0b1110, 0b0000, 0b010, 0b1) => {
            let reg_val = cntvct_el0();
            stack.store_reg(rt as usize, reg_val);
            //skip faulting instruction, A64 instructions are always 32-bits
            stack.iret.elr_el1 += 4;
            return true;
        }
        _ => {}
    }

    false
}

exception_stack!(synchronous_exception_at_el1_with_spx, |stack| {
    if !pf_inner(
        stack,
        exception_code(stack.iret.esr_el1),
        "sync_exc_el1_spx",
    ) {
        println!("Synchronous exception at EL1 with SPx");
        if exception_code(stack.iret.esr_el1) == 0b100101 {
            let far_el1 = far_el1();
            println!("FAR_EL1 = 0x{:08x}", far_el1);
        } else if exception_code(stack.iret.esr_el1) == 0b100100 {
            let far_el1 = far_el1();
            println!("USER FAR_EL1 = 0x{:08x}", far_el1);
        }
        stack.dump();
        stack_trace();
        loop {}
    }
});
unsafe fn pf_inner(stack: &mut InterruptStack, ty: u8, from: &str) -> bool {
    match ty {
        // "Data Abort taken from a lower Exception level"
        0b100100 => instr_data_abort_inner(stack, true, false, from),
        // "Data Abort taken without a change in Exception level"
        0b100101 => instr_data_abort_inner(stack, false, false, from),
        // "Instruction Abort taken from a lower Exception level"
        0b100000 => instr_data_abort_inner(stack, true, true, from),
        // "Instruction Abort taken without a change in Exception level"
        0b100001 => instr_data_abort_inner(stack, false, true, from),
        // "Trapped MSR, MRS or System instruction execution in AArch64 state"
        0b011000 => instr_trapped_msr_mrs_inner(stack, true, true, from),

        _ => return false,
    }
}

exception_stack!(synchronous_exception_at_el0, |stack| {
    match exception_code(stack.iret.esr_el1) {
        0b010101 => {
            let scratch = &stack.scratch;
            let ret = syscall::syscall(
                scratch.x8, scratch.x0, scratch.x1, scratch.x2, scratch.x3, scratch.x4,
            );
            stack.scratch.x0 = ret;
        }

        ty => {
            if !pf_inner(stack, ty as u8, "sync_exc_el0") {
                log::error!(
                    "FATAL: Not an SVC induced synchronous exception (ty={:b})",
                    ty
                );
                println!("FAR_EL1: {:#0x}", far_el1());
                //crate::debugger::debugger(None);
                stack.dump();
                stack_trace();
                crate::ksignal(SIGSEGV);
            }
        }
    }
});

exception_stack!(unhandled_exception, |stack| {
    println!("Unhandled exception");
    stack.dump();
    stack_trace();
    loop {}
});

impl ArchIntCtx for InterruptStack {
    fn ip(&self) -> usize {
        self.iret.elr_el1
    }
    fn recover_and_efault(&mut self) {
        // Set the return value to nonzero to indicate usercopy failure (EFAULT), and emulate the
        // return instruction by setting the return pointer to the saved LR value.

        self.iret.elr_el1 = self.preserved.x30;
        self.scratch.x0 = 1;
    }
}
