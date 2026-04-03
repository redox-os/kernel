/// Initialize MAIR
#[cold]
pub unsafe fn init() {
    unsafe {
        rmm::aarch64::init_mair();
    }
}
