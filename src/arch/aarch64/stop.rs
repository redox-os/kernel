use core::arch::asm;

#[no_mangle]
pub unsafe extern "C" fn kreset() -> ! {
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

#[no_mangle]
pub unsafe extern "C" fn kstop() -> ! {
    println!("kstop");

    let val: u32 = 0x8400_0008;
    asm!("mov   x0, {}", in(reg) val);
    asm!("hvc   #0", options(noreturn));
}
