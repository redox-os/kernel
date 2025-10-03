#[unsafe(no_mangle)]
pub unsafe extern "C" fn do_exception_unhandled() {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn do_exception_synchronous() {}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct SyscallStack {
    pub elr_el1: usize,
    pub padding: usize,
    pub tpidr: usize,
    pub tpidrro: usize,
    pub rflags: usize,
    pub esr: usize,
    pub sp: usize,
    pub lr: usize,
    pub fp: usize,
    pub x28: usize,
    pub x27: usize,
    pub x26: usize,
    pub x25: usize,
    pub x24: usize,
    pub x23: usize,
    pub x22: usize,
    pub x21: usize,
    pub x20: usize,
    pub x19: usize,
    pub x18: usize,
    pub x17: usize,
    pub x16: usize,
    pub x15: usize,
    pub x14: usize,
    pub x13: usize,
    pub x12: usize,
    pub x11: usize,
    pub x10: usize,
    pub x9: usize,
    pub x8: usize,
    pub x7: usize,
    pub x6: usize,
    pub x5: usize,
    pub x4: usize,
    pub x3: usize,
    pub x2: usize,
    pub x1: usize,
    pub x0: usize,
}
pub use super::handler::enter_usermode;
