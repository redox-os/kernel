use core::sync::atomic::Ordering;

use crate::{context, syscall::flag::SigcontrolFlags};

pub fn signal_handler() {
    let context_lock = context::current();
    let mut context_guard = context_lock.write();
    let context = &mut *context_guard;

    let being_sigkilled = context.being_sigkilled;

    if being_sigkilled {
        drop(context_guard);
        drop(context_lock);
        crate::syscall::process::exit_this_context(None);
    }

    /*let thumbs_down = ptrace::breakpoint_callback(
        PTRACE_STOP_SIGNAL,
        Some(ptrace_event!(PTRACE_STOP_SIGNAL)),
    )
    .and_then(|_| ptrace::next_breakpoint().map(|f| f.contains(PTRACE_FLAG_IGNORE)));*/

    // TODO: thumbs_down
    let Some((thread_ctl, proc_ctl, st)) = context.sigcontrol() else {
        // Discard signal if sigcontrol is unset.
        log::trace!("no sigcontrol, returning");
        return;
    };
    if thread_ctl.currently_pending_unblocked(proc_ctl) == 0 {
        // The context is currently Runnable. When transitioning into Blocked, it will check for
        // signals (with the context lock held, which is required when sending signals). After
        // that, any detection of pending unblocked signals by the sender, will result in the
        // context being unblocked, and signals sent.

        // TODO: prioritize signals over regular program execution
        return;
    }
    let control_flags =
        SigcontrolFlags::from_bits_retain(thread_ctl.control_flags.load(Ordering::Acquire));

    if control_flags.contains(SigcontrolFlags::INHIBIT_DELIVERY) {
        // Signals are inhibited to protect critical sections inside libc, but this code will run
        // every time the context is switched to.
        log::trace!("Inhibiting delivery, returning");
        return;
    }

    let sigh_instr_ptr = st.user_handler.get();

    let Some(regs) = context.regs_mut() else {
        // TODO: is this even reachable?
        log::trace!("No registers, returning");
        return;
    };

    let ip = regs.instr_pointer();
    let archdep_reg = regs.sig_archdep_reg();

    regs.set_instr_pointer(sigh_instr_ptr);

    let (thread_ctl, _, _) = context
        .sigcontrol()
        .expect("cannot have been unset while holding the lock");

    thread_ctl.saved_ip.set(ip);
    thread_ctl.saved_archdep_reg.set(archdep_reg);

    thread_ctl.control_flags.store(
        (control_flags | SigcontrolFlags::INHIBIT_DELIVERY).bits(),
        Ordering::Release,
    );
}
pub fn excp_handler(excp: syscall::Exception) {
    let current = context::current();

    let mut context = current.write();

    let Some(eh) = context.sig.as_ref().and_then(|s| s.excp_handler) else {
        // TODO: Let procmgr print this?
        log::info!(
            "UNHANDLED EXCEPTION, CPU {}, PID {}, NAME {}, CONTEXT {current:p}",
            crate::cpu_id(),
            context.pid,
            context.name
        );
        drop(context);
        // TODO: Allow exceptions to be caught by tracer etc, without necessarily exiting the
        // context (closing files, dropping AddrSpace, etc)
        crate::syscall::process::exit_this_context(Some(excp));
    };
    // TODO
    /*
    let Some(regs) = context.regs_mut() else {
        // TODO: unhandled exception in this case too?
        return;
    };
    let old_ip = regs.instr_pointer();
    let old_archdep_reg = regs.ar
    let (tctl, pctl, sigst) = context.sigcontrol().expect("already checked");
    tctl.saved_ip.set(excp.rsp);
    tctl.saved_archdep_reg*/
}
