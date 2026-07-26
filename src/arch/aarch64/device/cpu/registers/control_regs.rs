#![allow(unused)]

//! Functions to read and write control registers.

use core::arch::asm;

const ARM_IMPLEMENTER: u32 = 0x41;
const CORTEX_A53_PART: u32 = 0xd03;
const CORTEX_A35_PART: u32 = 0xd04;
const CORTEX_A73_PART: u32 = 0xd09;
pub const CPUECTLR_SMPEN: u64 = 1 << 6;

/// These pre-DynamIQ Arm cores use CPUECTLR_EL1.SMPEN to join the cluster's
/// hardware coherency domain. Newer cores such as Cortex-A55 use hardware
/// assisted coherency and do not expose this contract at the same encoding.
pub fn requires_cpuectlr_smpen(midr: u32) -> bool {
    let implementer = midr >> 24;
    let part = (midr >> 4) & 0xfff;
    implementer == ARM_IMPLEMENTER
        && matches!(part, CORTEX_A35_PART | CORTEX_A53_PART | CORTEX_A73_PART)
}

/// Read the implementation-defined CPUECTLR_EL1 used by Cortex-A35/A53/A73.
///
/// # Safety
///
/// Call only after `requires_cpuectlr_smpen` accepted the local MIDR.
pub unsafe fn cpuectlr_el1() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, S3_1_C15_C2_1", out(reg) ret, options(nomem, nostack));
        ret
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

pub unsafe fn tcr_el1() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, tcr_el1", out(reg) ret);
        ret
    }
}

pub unsafe fn mair_el1() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, mair_el1", out(reg) ret);
        ret
    }
}

pub unsafe fn sctlr_el1() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, sctlr_el1", out(reg) ret);
        ret
    }
}

pub unsafe fn vbar_el1() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, vbar_el1", out(reg) ret);
        ret
    }
}

pub unsafe fn cpacr_el1() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, cpacr_el1", out(reg) ret);
        ret
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

pub unsafe fn cntvct_el0() -> u64 {
    unsafe {
        let ret: u64;
        asm!("isb", "mrs {}, cntvct_el0", out(reg) ret, options(nomem, nostack));
        ret
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

pub unsafe fn mpidr() -> u64 {
    unsafe {
        let ret: u64;
        asm!("mrs {}, mpidr_el1", out(reg) ret);
        ret
    }
}
