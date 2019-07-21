use alloc::sync::Arc;
use core::mem;

use crate::context::{contexts, switch, Status, WaitpidKey};
use crate::start::usermode;
use crate::{ptrace, syscall};
use crate::syscall::flag::{PTRACE_EVENT_SIGNAL, PTRACE_SIGNAL, SIG_DFL, SIG_IGN, SIGCHLD, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU};
use crate::syscall::data::{PtraceEvent, PtraceEventData};

pub fn is_user_handled(handler: Option<extern "C" fn(usize)>) -> bool {
    let handler = handler.map(|ptr| ptr as usize).unwrap_or(0);
    handler != SIG_DFL && handler != SIG_IGN
}

pub extern "C" fn signal_handler(sig: usize) {
    let (action, restorer) = {
        let contexts = contexts();
        let context_lock = contexts.current().expect("context::signal_handler not inside of context");
        let context = context_lock.read();
        let actions = context.actions.lock();
        actions[sig]
    };

    ptrace::send_event(PtraceEvent {
        tag: PTRACE_EVENT_SIGNAL,
        data: PtraceEventData { signal: sig }
    });

    let handler = action.sa_handler.map(|ptr| ptr as usize).unwrap_or(0);
    if handler == SIG_DFL {
        match sig {
            SIGCHLD => {
                // println!("SIGCHLD");
            },
            SIGCONT => {
                // println!("Continue");

                {
                    let contexts = contexts();

                    let (pid, pgid, ppid) = {
                        let context_lock = contexts.current().expect("context::signal_handler not inside of context");
                        let mut context = context_lock.write();
                        context.status = Status::Runnable;
                        (context.id, context.pgid, context.ppid)
                    };

                    if let Some(parent_lock) = contexts.get(ppid) {
                        let waitpid = {
                            let parent = parent_lock.write();
                            Arc::clone(&parent.waitpid)
                        };

                        waitpid.send(WaitpidKey {
                            pid: Some(pid),
                            pgid: Some(pgid)
                        }, (pid, 0xFFFF));
                    } else {
                        println!("{}: {} not found for continue", pid.into(), ppid.into());
                    }
                }
            },
            SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => {
                // println!("Stop {}", sig);

                {
                    let contexts = contexts();

                    let (pid, pgid, ppid) = {
                        let context_lock = contexts.current().expect("context::signal_handler not inside of context");
                        let mut context = context_lock.write();
                        context.status = Status::Stopped(sig);
                        (context.id, context.pgid, context.ppid)
                    };

                    if let Some(parent_lock) = contexts.get(ppid) {
                        let waitpid = {
                            let parent = parent_lock.write();
                            Arc::clone(&parent.waitpid)
                        };

                        waitpid.send(WaitpidKey {
                            pid: Some(pid),
                            pgid: Some(pgid)
                        }, (pid, (sig << 8) | 0x7F));
                    } else {
                        println!("{}: {} not found for stop", pid.into(), ppid.into());
                    }
                }

                unsafe { switch() };
            },
            _ => {
                // println!("Exit {}", sig);
                syscall::exit(sig);
            }
        }
    } else if handler == SIG_IGN {
        // println!("Ignore");
    } else {
        // println!("Call {:X}", handler);

        ptrace::breakpoint_callback(PTRACE_SIGNAL);

        unsafe {
            let mut sp = crate::USER_SIGSTACK_OFFSET + crate::USER_SIGSTACK_SIZE - 256;

            sp = (sp / 16) * 16;

            sp -= mem::size_of::<usize>();
            *(sp as *mut usize) = restorer;

            usermode(handler, sp, sig);
        }
    }

    syscall::sigreturn().unwrap();
}
