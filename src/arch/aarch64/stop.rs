use core::arch::asm;

#[no_mangle]
pub unsafe extern fn kreset() -> ! {
    println!("kreset");

    let val: u32 = 0x8400_0009;
    asm!("mov   x0, {}", in(reg) val);
    asm!("hvc   #0");

    unreachable!();
}

#[no_mangle]
pub unsafe extern fn kstop() -> ! {
    println!("kstop");

    let val: u32 = 0x8400_0008;
    asm!("mov   x0, {}", in(reg) val);
    asm!("hvc   #0");

    unreachable!();
}
