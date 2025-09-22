use crate::sync::CleanLockToken;

pub unsafe fn kreset() -> ! {
    println!("kreset");
    unimplemented!()
}

pub unsafe fn emergency_reset() -> ! {
    unimplemented!()
}

pub unsafe fn kstop(token: &mut CleanLockToken) -> ! {
    println!("kstop");
    unimplemented!()
}
