use sbi_rt::{ColdReboot, NoReason, ResetType, Shutdown, SystemFailure};

use crate::sync::CleanLockToken;

pub unsafe fn kreset() -> ! {
    println!("kreset");
    sbi_rt::system_reset(ColdReboot, NoReason).unwrap();
    panic!("Failed to reset system through SBI!")
}

pub unsafe fn emergency_reset() -> ! {
    println!("emergency reset");
    // is system failure appropriate here?
    sbi_rt::system_reset(ColdReboot, SystemFailure).unwrap();
    panic!("Failed to reset system through SBI!")
}

pub unsafe fn kstop(_token: &mut CleanLockToken) -> ! {
    println!("kstop");
    sbi_rt::system_reset(Shutdown, NoReason).unwrap();
    panic!("Failed to stop system through SBI!")
}
