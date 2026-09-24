use core::sync::atomic::Ordering;

use alloc::sync::Arc;

use crate::{
    context::{self, Context},
    sync::CleanLockToken,
    syscall::flag::SigcontrolFlags,
};

pub fn signal_handler(token: &mut CleanLockToken) {
    let context_lock = context::current();
    let context = context_lock.upgradeable_read(token.token());

    let being_sigkilled = context.being_sigkilled;

    if being_sigkilled {
        drop(context);
        drop(context_lock);
        crate::syscall::process::exit_this_context(None, token);
    }

    /*let thumbs_down = ptrace::breakpoint_callback(
        PTRACE_STOP_SIGNAL,
        Some(ptrace_event!(PTRACE_STOP_SIGNAL)),
    )
    .and_then(|_| ptrace::next_breakpoint().map(|f| f.contains(PTRACE_FLAG_IGNORE)));*/

    // TODO: thumbs_down
    let Some((thread_ctl, proc_ctl, st)) = context.sigcontrol() else {
        // Discard signal if sigcontrol is unset.
        trace!("no sigcontrol, returning");
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
        trace!("Inhibiting delivery, returning");
        return;
    }

    let sigh_instr_ptr = st.user_handler.get();

    let mut context = context.upgrade();
    let Some(regs) = context.regs_mut() else {
        // TODO: is this even reachable?
        trace!("No registers, returning");
        return;
    };

    let ip = regs.instr_pointer();
    let archdep_reg = regs.sig_archdep_reg();

    regs.set_instr_pointer(sigh_instr_ptr);

    let context = context.downgrade();
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

// TODO: move print logs from callers to this function
pub fn excp_handler(excp: syscall::Exception) {
    let mut token = unsafe { CleanLockToken::new() };

    let current = context::current();

    let mut context = current.write(token.token());

    if !excp_handler_inner(excp, &mut context) {
        // TODO: Let procmgr print this?
        info!(
            "UNHANDLED EXCEPTION, CPU {}, PID {}, NAME {}, CONTEXT {:p}",
            crate::cpu_id(),
            context.pid,
            context.name,
            Arc::as_ptr(&*current),
        );
        drop(context);
        drop(current);
        // TODO: Allow exceptions to be caught by tracer etc, without necessarily exiting the
        // context (closing files, dropping AddrSpace, etc)
        crate::syscall::process::exit_this_context(Some(excp), &mut token);
    }
}

/// Return true if handled by user
fn excp_handler_inner(excp: syscall::Exception, context: &mut Context) -> bool {
    let Some(eh) = context.sig.as_ref().and_then(|s| s.excp_handler) else {
        return false;
    };

    let control_flags = {
        let (tctl, _pctl, _sigst) = context.sigcontrol().expect("Failed to get sigcontrol");
        let control_flags =
            SigcontrolFlags::from_bits_retain(tctl.control_flags.load(Ordering::Acquire));

        if control_flags.contains(SigcontrolFlags::HANDLING_EXCEPTION) {
            // double fault
            return false;
        }
        control_flags
    };

    let Some(regs) = context.regs_mut() else {
        // probably a kernel exception
        trace!("No registers upon exception, returning");
        return false;
    };

    let (ip, archdep_reg) = (regs.instr_pointer(), regs.sig_archdep_reg());
    regs.set_instr_pointer(eh.get());
    {
        let (tctl, _pctl, _sigst) = context.sigcontrol().expect("Failed to get sigcontrol");

        let (code, addr) = excp.pack();

        tctl.saved_ip.set(ip);
        tctl.saved_archdep_reg.set(archdep_reg);
        tctl.saved_excp_code.set(code);
        tctl.saved_excp_addr.set(addr);
        tctl.control_flags.store(
            (control_flags
                | SigcontrolFlags::INHIBIT_DELIVERY
                | SigcontrolFlags::HANDLING_EXCEPTION)
                .bits(),
            Ordering::Release,
        );
    };

    true
}
