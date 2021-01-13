#[no_mangle]
pub unsafe extern fn kreset() -> ! {
    println!("kreset");

    let val: u32 = 0x8400_0009;
    llvm_asm!("mov   x0, $0" : : "r"(val) : : "volatile");
    llvm_asm!("hvc   #0" : : : : "volatile");

    unreachable!();
}

#[no_mangle]
pub unsafe extern fn kstop() -> ! {
    println!("kstop");

    let val: u32 = 0x8400_0008;
    llvm_asm!("mov   x0, $0" : : "r"(val) : : "volatile");
    llvm_asm!("hvc   #0" : : : : "volatile");

    unreachable!();
}
