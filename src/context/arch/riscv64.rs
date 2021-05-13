use core::mem;
use core::sync::atomic::AtomicBool;

use crate::syscall::FloatRegisters;

/// This must be used by the kernel to ensure that context switches are done atomically
/// Compare and exchange this to true when beginning a context switch on any CPU
/// The `Context::switch_to` function will set it back to false, allowing other CPU's to switch
/// This must be done, as no locks can be held on the stack during switch
pub static CONTEXT_SWITCH_LOCK: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Context {
    satp: usize,
    sp: usize,
    gp: usize,
    tp: usize,
    s0: usize,
    s1: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
    fx: usize,
}

impl Context {
    pub fn new() -> Context {
        Context {
            satp: 0,
            sp: 0,
            gp: 0,
            tp: 0,
            s0: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
            fx: 0,
        }
    }

    pub fn get_page_utable(&mut self) -> usize {
        self.satp
    }

    pub fn set_fx(&mut self, address: usize) {
        self.fx = address;
    }


    pub fn set_page_utable(&mut self, address: usize) {
        self.satp = address;
    }

    pub fn set_stack(&mut self, address: usize) {
        self.sp = address;
    }

    pub unsafe fn signal_stack(&mut self, handler: extern fn(usize), sig: u8) {
        self.push_stack(sig as usize);
        self.push_stack(handler as usize);
        self.push_stack(signal_handler_wrapper as usize);
    }

    pub unsafe fn push_stack(&mut self, value: usize) {
        self.sp -= mem::size_of::<usize>();
        *(self.sp as *mut usize) = value;
    }

    pub unsafe fn pop_stack(&mut self) -> usize {
        let value = *(self.sp as *const usize);
        self.sp += mem::size_of::<usize>();
        value
    }
}

/// Switch to the next context by restoring its stack and registers
/// Check disassembly!
#[cold]
#[inline(never)]
#[naked]
pub unsafe extern "C" fn switch_to(_prev: &mut Context, _next: &mut Context) {
    panic!("switch_to");
}

#[naked]
unsafe extern fn signal_handler_wrapper() {
    panic!("signal_handler_wrapper");
}
