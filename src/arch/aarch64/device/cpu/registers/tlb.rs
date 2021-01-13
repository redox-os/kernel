//! Functions to flush the translation lookaside buffer (TLB).

pub unsafe fn flush(_addr: usize) {
    llvm_asm!("tlbi vmalle1is");
}

pub unsafe fn flush_all() {
    llvm_asm!("tlbi vmalle1is");
}
