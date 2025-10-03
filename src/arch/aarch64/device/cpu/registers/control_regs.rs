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
    unsafe {
        let ret: u64;
        asm!("mrs {}, ttbr0_el1", out(reg) ret);
        ret
    }
}

pub unsafe fn ttbr0_el1_write(val: u64) {
    unsafe {
        asm!("msr ttbr0_el1, {}", in(reg) val);
    }
}

pub unsafe fn ttbr1_el1() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, ttbr1_el1", out(reg) ret);
        ret
    }
}

pub unsafe fn ttbr1_el1_write(val: u64) {
    unsafe {
        asm!("msr ttbr1_el1, {}", in(reg) val);
    }
}

pub unsafe fn mair_el1() -> MairEl1 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, mair_el1", out(reg) ret);
        MairEl1::from_bits_truncate(ret)
    }
}

pub unsafe fn mair_el1_write(val: MairEl1) {
    unsafe {
        asm!("msr mair_el1, {}", in(reg) val.bits());
    }
}

pub unsafe fn tpidr_el0() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, tpidr_el0", out(reg) ret);
        ret
    }
}

pub unsafe fn tpidr_el0_write(val: u64) {
    unsafe {
        asm!("msr tpidr_el0, {}", in(reg) val);
    }
}

pub unsafe fn tpidr_el1() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, tpidr_el1", out(reg) ret);
        ret
    }
}

pub unsafe fn tpidr_el1_write(val: u64) {
    unsafe {
        asm!("msr tpidr_el1, {}", in(reg) val);
    }
}

pub unsafe fn tpidrro_el0() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, tpidrro_el0", out(reg) ret);
        ret
    }
}

pub unsafe fn tpidrro_el0_write(val: u64) {
    unsafe {
        asm!("msr tpidrro_el0, {}", in(reg) val);
    }
}

pub unsafe fn esr_el1() -> u32 {
    unsafe {
        let ret: u32;
        asm!("mrs {0:w}, esr_el1", out(reg) ret);
        ret
    }
}

pub unsafe fn vhe_present() -> bool {
    unsafe {
        let mut mmfr1: u64;
        asm!("mrs {}, id_aa64mmfr1_el1", out(reg) mmfr1);

        // The VHE (Virtualization Host Extensions) field is in bits [7:4].
        let vhe_field = (mmfr1 >> 4) & 0b1111;

        vhe_field != 0
    }
}

pub unsafe fn cntfrq_el0() -> u32 {
    unsafe {
        let ret: usize;
        asm!("mrs {}, cntfrq_el0", out(reg) ret);
        ret as u32
    }
}

pub unsafe fn ptmr_ctrl() -> u32 {
    unsafe {
        let ret: usize;
        asm!("mrs {}, cntp_ctl_el0", out(reg) ret);
        ret as u32
    }
}

pub unsafe fn ptmr_ctrl_write(val: u32) {
    unsafe {
        asm!("msr cntp_ctl_el0, {}", in(reg) val as usize);
    }
}

pub unsafe fn ptmr_tval() -> u32 {
    unsafe {
        let ret: usize;
        asm!("mrs {0}, cntp_tval_el0", out(reg) ret);
        ret as u32
    }
}

pub unsafe fn ptmr_tval_write(val: u32) {
    unsafe {
        asm!("msr cntp_tval_el0, {}", in(reg) val as usize);
    }
}

pub unsafe fn vtmr_ctrl() -> u32 {
    unsafe {
        let ret: usize;
        asm!("mrs {}, cntv_ctl_el0", out(reg) ret);
        ret as u32
    }
}

pub unsafe fn vtmr_ctrl_write(val: u32) {
    unsafe {
        asm!("msr cntv_ctl_el0, {}", in(reg) val as usize);
    }
}

pub unsafe fn vtmr_tval() -> u32 {
    unsafe {
        let ret: usize;
        asm!("mrs {0}, cntv_tval_el0", out(reg) ret);
        ret as u32
    }
}

pub unsafe fn vtmr_tval_write(val: u32) {
    unsafe {
        asm!("msr cntv_tval_el0, {}", in(reg) val as usize);
    }
}

pub unsafe fn midr() -> u32 {
    unsafe {
        let ret: usize;
        asm!("mrs {}, midr_el1", out(reg) ret);
        ret as u32
    }
}
