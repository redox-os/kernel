use alloc::sync::Arc;
use core::mem::{self, size_of};
use syscall::{
    flag::{
        PTRACE_FLAG_IGNORE, PTRACE_STOP_SIGNAL, SIGCHLD, SIGCONT, SIGKILL, SIGSTOP, SIGTSTP,
        SIGTTIN, SIGTTOU, SIG_DFL, SIG_IGN,
    },
    ptrace_event, SignalStack, SigActionFlags, IntRegisters,
};

use crate::{
    context::{self, switch, Status, WaitpidKey},
    ptrace,
    syscall::usercopy::UserSlice,
};

pub fn is_user_handled(handler: Option<extern "C" fn(usize)>) -> bool {
    let handler = handler.map(|ptr| ptr as usize).unwrap_or(0);
    handler != SIG_DFL && handler != SIG_IGN
}

// TODO: Move everything but SIGKILL to userspace. SIGCONT and SIGSTOP does not necessarily need to
// be done from this current context.
pub fn signal_handler() {
    let (action, sig) = {
        // FIXME: Can any low-level state become corrupt if a panic occurs here?
        let context_lock = context::current().expect("context::signal_handler not inside of context");
        let mut context = context_lock.write();

        // Lowest-numbered signal first.
        // TODO: randomly?
        let selected = context.sig.deliverable().trailing_zeros() as usize + 1;
        context.sig.pending &= !(1 << (selected - 1));

        let actions = context.actions.read();
        (actions[selected - 1].0, selected)
    };

    let handler = action.sa_handler.map(|ptr| ptr as usize).unwrap_or(0);

    let thumbs_down = ptrace::breakpoint_callback(
        PTRACE_STOP_SIGNAL,
        Some(ptrace_event!(PTRACE_STOP_SIGNAL, sig, handler)),
    )
    .and_then(|_| ptrace::next_breakpoint().map(|f| f.contains(PTRACE_FLAG_IGNORE)));

    if sig != SIGKILL && thumbs_down.unwrap_or(false) {
        // If signal can be and was ignored
        crate::syscall::sigreturn().unwrap();
        unreachable!();
    }

    if handler == SIG_DFL {
        match sig {
            SIGCHLD => {
                // println!("SIGCHLD");
            }
            SIGCONT => {
                // println!("Continue");

                {
                    let contexts = context::contexts();

                    let (pid, pgid, ppid) = {
                        let context_lock = contexts
                            .current()
                            .expect("context::signal_handler not inside of context");
                        let mut context = context_lock.write();
                        context.status = Status::Runnable;
                        (context.id, context.pgid, context.ppid)
                    };

                    if let Some(parent_lock) = contexts.get(ppid) {
                        let waitpid = {
                            let parent = parent_lock.write();
                            Arc::clone(&parent.waitpid)
                        };

                        waitpid.send(
                            WaitpidKey {
                                pid: Some(pid),
                                pgid: Some(pgid),
                            },
                            (pid, 0xFFFF),
                        );
                    } else {
                        println!("{}: {} not found for continue", pid.get(), ppid.get());
                    }
                }
            }
            SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => {
                // println!("Stop {}", sig);

                {
                    let contexts = context::contexts();

                    let (pid, pgid, ppid) = {
                        let context_lock = contexts
                            .current()
                            .expect("context::signal_handler not inside of context");
                        let mut context = context_lock.write();
                        context.status = Status::Stopped(sig);
                        (context.id, context.pgid, context.ppid)
                    };

                    if let Some(parent_lock) = contexts.get(ppid) {
                        let waitpid = {
                            let parent = parent_lock.write();
                            Arc::clone(&parent.waitpid)
                        };

                        waitpid.send(
                            WaitpidKey {
                                pid: Some(pid),
                                pgid: Some(pgid),
                            },
                            (pid, (sig << 8) | 0x7F),
                        );
                    } else {
                        println!("{}: {} not found for stop", pid.get(), ppid.get());
                    }
                }

                unsafe { switch() };
            }
            _ => {
                // println!("Exit {}", sig);
                crate::syscall::exit(sig);
            }
        }
    } else if handler == SIG_IGN {
        // println!("Ignore");
    } else {
        // println!("Call {:X}", handler);

        // TODO: Move more of this to userspace
        let context_lock = context::current()
            .expect("context::signal_handler not inside of context");
        let mut context = context_lock.write();

        let Some(handler) = context.sig.handler else {
            log::debug!("signal ignored since context did not setup sighandler");
            return;
        };
        let Some(regs) = context.regs_mut() else {
            log::warn!("cannot send signal to context without userspace registers");
            return;
        };

        let mut intregs = IntRegisters::default();
        regs.save(&mut intregs);

        const STACK_ADJUST: usize = 256;
        // TODO: 16 bytes alignment is sufficient unless XSAVE is enabled.
        const STACK_ALIGN: usize = 64;

        let new_sp_unless_altstack = (regs.stack_pointer() - STACK_ADJUST) & usize::wrapping_neg(STACK_ALIGN);

        let new_sp = match handler.altstack {
            Some(altstack) if !(altstack.base.get()..altstack.base.get() + altstack.base.get() + altstack.len.get()).contains(&regs.stack_pointer()) => altstack.base.get() + altstack.len.get(),
            _ => new_sp_unless_altstack,
        } - size_of::<SignalStack>();

        let old_procmask = context.sig.procmask;

        context.sig.procmask |= action.sa_mask;

        if !action.sa_flags.contains(SigActionFlags::SA_NODEFER) {
            context.sig.procmask &= !(1 << (sig - 1));
        }

        let Some(regs) = context.regs_mut() else {
            return;
        };

        regs.set_stack_pointer(new_sp);
        regs.set_instr_pointer(handler.handler.get());

        drop(context);

        let Ok(slice) = UserSlice::wo(new_sp, size_of::<SignalStack>()) else {
            return;
        };
        let stack = SignalStack {
            intregs,
            old_procmask,
            sa_mask: action.sa_mask,
            sa_flags: action.sa_flags.bits() as u32,
            sig_num: sig as u32,
            sa_handler: action.sa_handler.map_or(0, |h| h as usize),
        };
        let Ok(()) = slice.copy_from_slice(&stack) else {
            return;
        };
    }
}
