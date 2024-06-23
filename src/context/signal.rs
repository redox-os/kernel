use alloc::sync::Arc;
use core::mem::size_of;
use syscall::{
    flag::{
        PTRACE_FLAG_IGNORE, PTRACE_STOP_SIGNAL, SIGCHLD, SIGCONT, SIGKILL, SIGSTOP, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU
    },
    ptrace_event, IntRegisters, SigcontrolFlags,
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
    let context_lock = context::current().expect("running signal handler outside of context");
    let mut context = context_lock.write();
    let context = &mut *context;

    if context.being_sigkilled {
        crate::syscall::process::exit(SIGKILL << 8);
    }

    let thumbs_down = ptrace::breakpoint_callback(
        PTRACE_STOP_SIGNAL,
        Some(ptrace_event!(PTRACE_STOP_SIGNAL)),
    )
    .and_then(|_| ptrace::next_breakpoint().map(|f| f.contains(PTRACE_FLAG_IGNORE)));

    // TODO: thumbs_down
    let Some((thread_ctl, proc_ctl, st)) = context.sigcontrol() else {
        // Discard signal if sigcontrol is unset.
        return;
    };
    if unsafe { thread_ctl.control_flags.get().read() }.contains(SigcontrolFlags::INHIBIT_DELIVERY) {
        // Signals are inhibited to protect critical sections inside libc, but this code will run
        // every time the context is switched to.
        return;
    }

    if !core::mem::take(&mut st.is_pending) {
        return;
    }

    let Some(regs) = context.regs_mut() else {
        // TODO: is this even reachable?
        return;
    };

    let ip = regs.instr_pointer();
    let sp = regs.stack_pointer();
    let fl = regs.flags();
    let scratch_a = regs.scratch.a();
    let scratch_b = regs.scratch.b();

    let (thread_ctl, _, _) = context.sigcontrol()
        .expect("cannot have been unset while holding the lock");

    unsafe {
        thread_ctl.saved_ip.get().write_volatile(ip);
        thread_ctl.saved_sp.get().write_volatile(sp);
        thread_ctl.saved_flags.get().write_volatile(fl);
        thread_ctl.saved_scratch_a.get().write_volatile(scratch_a);
        thread_ctl.saved_scratch_b.get().write_volatile(scratch_b);
        (*thread_ctl.control_flags.get()) |= SigcontrolFlags::INHIBIT_DELIVERY;
    }
}
pub fn excp_handler(signal: usize) {
     let current = context::current().expect("CPU exception but not inside of context!");
     let mut context = current.write();

     let Some(eh) = context.sig.as_ref().and_then(|s| s.excp_handler) else {
         context.being_sigkilled = true;
         context::switch();

         unreachable!();
     };

     // TODO
}
