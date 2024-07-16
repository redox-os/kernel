#![allow(unused)]

//! Functions to read and write control registers.

use core::arch::asm;

bitflags! {
    pub struct MairEl1: u64 {
        const DEVICE_MEMORY = 0x00 << 16;
        const NORMAL_UNCACHED_MEMORY = 0x44 << 8;
        const NORMAL_WRITEBACK_MEMORY = 0xff;
    }
}

pub unsafe fn ttbr0_el1() -> u64 {
    let ret: u64;
    asm!("mrs {}, ttbr0_el1", out(reg) ret);
    ret
}

pub unsafe fn ttbr0_el1_write(val: u64) {
    asm!("msr ttbr0_el1, {}", in(reg) val);
}

pub unsafe fn ttbr1_el1() -> u64 {
    let ret: u64;
    asm!("mrs {}, ttbr1_el1", out(reg) ret);
    ret
}

pub unsafe fn ttbr1_el1_write(val: u64) {
    asm!("msr ttbr1_el1, {}", in(reg) val);
}

pub unsafe fn mair_el1() -> MairEl1 {
    let ret: u64;
    asm!("mrs {}, mair_el1", out(reg) ret);
    MairEl1::from_bits_truncate(ret)
}

pub unsafe fn mair_el1_write(val: MairEl1) {
    asm!("msr mair_el1, {}", in(reg) val.bits());
}

pub unsafe fn tpidr_el0() -> u64 {
    let ret: u64;
    asm!("mrs {}, tpidr_el0", out(reg) ret);
    ret
}

pub unsafe fn tpidr_el0_write(val: u64) {
    asm!("msr tpidr_el0, {}", in(reg) val);
}

pub unsafe fn tpidr_el1() -> u64 {
    let ret: u64;
    asm!("mrs {}, tpidr_el1", out(reg) ret);
    ret
}

pub unsafe fn tpidr_el1_write(val: u64) {
    asm!("msr tpidr_el1, {}", in(reg) val);
}

pub unsafe fn tpidrro_el0() -> u64 {
    let ret: u64;
    asm!("mrs {}, tpidrro_el0", out(reg) ret);
    ret
}

pub unsafe fn tpidrro_el0_write(val: u64) {
    asm!("msr tpidrro_el0, {}", in(reg) val);
}

pub unsafe fn esr_el1() -> u32 {
    let ret: u32;
    asm!("mrs {0:w}, esr_el1", out(reg) ret);
    ret
}

pub unsafe fn cntfreq_el0() -> u32 {
    let ret: usize;
    asm!("mrs {}, cntfrq_el0", out(reg) ret);
    ret as u32
}

pub unsafe fn tmr_ctrl() -> u32 {
    let ret: usize;
    asm!("mrs {}, cntp_ctl_el0", out(reg) ret);
    ret as u32
}

pub unsafe fn tmr_ctrl_write(val: u32) {
    asm!("msr cntp_ctl_el0, {}", in(reg) val as usize);
}

pub unsafe fn tmr_tval() -> u32 {
    let ret: usize;
    asm!("mrs {0}, cntp_tval_el0", out(reg) ret);
    ret as u32
}

pub unsafe fn tmr_tval_write(val: u32) {
    asm!("msr cntp_tval_el0, {}", in(reg) val as usize);
}

pub unsafe fn midr() -> u32 {
    let ret: usize;
    asm!("mrs {}, midr_el1", out(reg) ret);
    ret as u32
}
