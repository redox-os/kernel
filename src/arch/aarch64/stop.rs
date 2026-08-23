use crate::{arch::device::psci, sync::CleanLockToken};

fn halt_after_failed_psci(operation: &str, error: psci::CallError) -> ! {
    error!("PSCI {} failed: {:?}", operation, error);
    loop {
        unsafe {
            crate::arch::interrupt::disable();
            crate::arch::interrupt::halt();
        }
    }
}

pub unsafe fn kreset() -> ! {
    println!("kreset");
    match psci::system_reset() {
        Ok(()) => unreachable!(),
        Err(error) => halt_after_failed_psci("SYSTEM_RESET", error),
    }
}

pub unsafe fn emergency_reset() -> ! {
    match psci::system_reset() {
        Ok(()) => unreachable!(),
        Err(error) => halt_after_failed_psci("SYSTEM_RESET", error),
    }
}

pub unsafe fn kstop(_token: &mut CleanLockToken) -> ! {
    println!("kstop");
    match psci::system_off() {
        Ok(()) => unreachable!(),
        Err(error) => halt_after_failed_psci("SYSTEM_OFF", error),
    }
}
