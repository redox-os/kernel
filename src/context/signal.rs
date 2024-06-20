use alloc::sync::Arc;
use core::mem::size_of;
use syscall::{
    flag::{
        PTRACE_FLAG_IGNORE, PTRACE_STOP_SIGNAL, SIGCHLD, SIGCONT, SIGKILL, SIGSTOP, SIGTSTP,
        SIGTTIN, SIGTTOU, SIGTERM,
    },
    ptrace_event, IntRegisters,
};

use crate::{
    context::{self, switch, Status, WaitpidKey},
    ptrace,
    syscall::usercopy::UserSlice, stop::{kstop, kreset},
};

use super::ContextId;

pub fn kmain_signal_handler() {
    /*if context::context_id() != ContextId::new(1) {
        log::warn!("kmain signal didn't target PID 1, ignoring");
        return;
    }

    let deliverable = context::current().expect("context::kmain_signal_handler not inside of context");
    let kstop_bit = 1 << (SIGKILL - 1);
    let kreset_bit = 1 << (SIGTERM - 1);
    let bits = deliverable.read().sig.deliverable();

    if bits & kstop_bit == kstop_bit {
        unsafe {
            kstop();
        }
    } else if bits & kreset_bit == kreset_bit {
        unsafe {
            kreset();
        }
    } else {
        log::warn!("Spurious kmain signal, bitmask {bits:#0x}.");
    }*/
}

pub fn signal_handler() {
    /*let thumbs_down = ptrace::breakpoint_callback(
        PTRACE_STOP_SIGNAL,
        Some(ptrace_event!(PTRACE_STOP_SIGNAL, sig, handler)),
    )
    .and_then(|_| ptrace::next_breakpoint().map(|f| f.contains(PTRACE_FLAG_IGNORE)));*/
}
pub fn excp_handler(signal: usize) {
     let Ok(current) = context::current() else {
         panic!("CPU exception but not inside of context! Trying to switch...");
     };
     let mut context = current.write();

     let Some(eh) = context.sig.as_ref().and_then(|s| s.excp_handler) else {
         context.being_sigkilled = true;
         context::switch();

         unreachable!();
     };

     // TODO
}
