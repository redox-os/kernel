use core::arch::asm;

pub unsafe fn kreset() -> ! {
    println!("kreset");

    let val: u32 = 0x8400_0009;
    asm!("mov   x0, {}", in(reg) val);
    asm!("hvc   #0", options(noreturn));
}

pub unsafe fn emergency_reset() -> ! {
    let val: u32 = 0x8400_0009;
    asm!("mov   x0, {}", in(reg) val);
    asm!("hvc   #0", options(noreturn));
}

pub unsafe fn kstop() -> ! {
    println!("kstop");

    let val: u32 = 0x8400_0008;
    asm!("mov   x0, {}", in(reg) val);
    asm!("hvc   #0", options(noreturn));
}
