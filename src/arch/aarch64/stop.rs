use crate::sync::CleanLockToken;
use core::arch::asm;

pub unsafe fn kreset() -> ! {
    unsafe {
        println!("kreset");

        asm!("hvc   #0",
             in("x0") 0x8400_0009_usize,
             options(noreturn),
        )
    }
}

pub unsafe fn emergency_reset() -> ! {
    unsafe {
        asm!("hvc   #0",
             in("x0")  0x8400_0009_usize,
             options(noreturn),
        )
    }
}

pub unsafe fn kstop(token: &mut CleanLockToken) -> ! {
    unsafe {
        println!("kstop");

        asm!("hvc   #0",
             in("x0")  0x8400_0008_usize,
             options(noreturn),
        )
    }
}
