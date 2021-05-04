//! Functions to read and write control registers.

bitflags! {
    pub struct MairEl1: u64 {
        const DEVICE_MEMORY = 0x00;
        const NORMAL_UNCACHED_MEMORY = 0x44 << 8;
        const NORMAL_WRITEBACK_MEMORY = 0xff << 16;
    }
}

pub unsafe fn ttbr0_el1() -> u64 {
    let ret: u64;
    llvm_asm!("mrs $0, ttbr0_el1" : "=r" (ret));
    ret
}

pub unsafe fn ttbr0_el1_write(val: u64) {
    llvm_asm!("msr ttbr0_el1, $0" :: "r" (val) : "memory");
}

pub unsafe fn ttbr1_el1() -> u64 {
    let ret: u64;
    llvm_asm!("mrs $0, ttbr1_el1" : "=r" (ret));
    ret
}

pub unsafe fn ttbr1_el1_write(val: u64) {
    llvm_asm!("msr ttbr1_el1, $0" :: "r" (val) : "memory");
}

pub unsafe fn mair_el1() -> MairEl1 {
    let ret: u64;
    llvm_asm!("mrs $0, mair_el1" : "=r" (ret));
    MairEl1::from_bits_truncate(ret)
}

pub unsafe fn mair_el1_write(val: MairEl1) {
    llvm_asm!("msr mair_el1, $0" :: "r" (val.bits()) : "memory");
}

pub unsafe fn tpidr_el0_write(val: u64) {
    llvm_asm!("msr tpidr_el0, $0" :: "r" (val) : "memory");
}

pub unsafe fn tpidr_el1_write(val: u64) {
    llvm_asm!("msr tpidr_el1, $0" :: "r" (val) : "memory");
}

pub unsafe fn esr_el1() -> u32 {
    let ret: u32;
    llvm_asm!("mrs $0, esr_el1" : "=r" (ret));
    ret
}

pub unsafe fn cntfreq_el0() -> u32 {
    let ret: u32;
    llvm_asm!("mrs $0, cntfrq_el0" : "=r" (ret));
    ret
}

pub unsafe fn tmr_ctrl() -> u32 {
    let ret: u32;
    llvm_asm!("mrs $0, cntp_ctl_el0" : "=r" (ret));
    ret
}

pub unsafe fn tmr_ctrl_write(val: u32) {
    llvm_asm!("msr cntp_ctl_el0, $0" :: "r" (val) : "memory");
}

pub unsafe fn tmr_tval() -> u32 {
    let ret: u32;
    llvm_asm!("mrs $0, cntp_tval_el0" : "=r" (ret));
    ret
}

pub unsafe fn tmr_tval_write(val: u32) {
    llvm_asm!("msr cntp_tval_el0, $0" :: "r" (val) : "memory");
}

pub unsafe fn midr() -> u32 {
    let ret: u32;
    llvm_asm!("mrs $0, midr_el1" : "=r" (ret));
    ret
}
