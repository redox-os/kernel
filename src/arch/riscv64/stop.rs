use crate::sync::CleanLockToken;
use sbi_rt::{system_reset, NoReason, SbiRet, Shutdown, SystemFailure, WarmReboot};

pub unsafe fn kreset() -> ! {
    info!("kreset");
    let ret = system_reset(WarmReboot, NoReason);
    halt_after_failed_reset("kreset", ret);
}

pub unsafe fn emergency_reset() -> ! {
    let ret = system_reset(WarmReboot, SystemFailure);
    halt_after_failed_reset("emergency_reset", ret);
}

pub unsafe fn kstop(_token: &mut CleanLockToken) -> ! {
    info!("kstop");
    let ret = system_reset(Shutdown, NoReason);
    halt_after_failed_reset("kstop", ret);
}

fn halt_after_failed_reset(operation: &str, ret: SbiRet) -> ! {
    error!("{} failed: {:?}", operation, ret);
    loop {
        unsafe {
            crate::arch::interrupt::disable();
            crate::arch::interrupt::halt();
        }
    }
}
