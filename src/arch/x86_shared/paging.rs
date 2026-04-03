/// Initialize PAT
#[cold]
pub unsafe fn init() {
    unsafe {
        #[cfg(target_arch = "x86")]
        rmm::x86::init_pat();
        #[cfg(target_arch = "x86_64")]
        rmm::x86_64::init_pat();
    }
}
