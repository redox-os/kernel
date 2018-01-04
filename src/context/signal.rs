use alloc::arc::Arc;
use core::mem;

use context::{contexts, switch, Status};
use start::usermode;
use syscall;
use syscall::flag::{SIG_DFL, SIG_IGN, SIGCHLD, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU};

pub extern "C" fn signal_handler(sig: usize) {
    let (action, restorer) = {
        let contexts = contexts();
        let context_lock = contexts.current().expect("context::signal_handler not inside of context");
        let context = context_lock.read();
        let actions = context.actions.lock();
        actions[sig]
    };

    let handler = action.sa_handler as usize;
    if handler == SIG_DFL {
        match sig {
            SIGCHLD => {
                println!("SIGCHLD");
            },
            SIGCONT => {
                println!("Continue");

                {
                    let contexts = contexts();

                    let (pid, ppid) = {
                        let context_lock = contexts.current().expect("context::signal_handler not inside of context");
                        let mut context = context_lock.write();
                        context.status = Status::Runnable;
                        (context.id, context.ppid)
                    };

                    if let Some(parent_lock) = contexts.get(ppid) {
                        let waitpid = {
                            let mut parent = parent_lock.write();
                            Arc::clone(&parent.waitpid)
                        };

                        waitpid.send(pid, 0xFFFF);
                    } else {
                        println!("{}: {} not found for continue", pid.into(), ppid.into());
                    }
                }
            },
            SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => {
                println!("Stop {}", sig);

                {
                    let contexts = contexts();

                    let (pid, ppid) = {
                        let context_lock = contexts.current().expect("context::signal_handler not inside of context");
                        let mut context = context_lock.write();
                        context.status = Status::Stopped(sig);
                        (context.id, context.ppid)
                    };

                    if let Some(parent_lock) = contexts.get(ppid) {
                        let waitpid = {
                            let mut parent = parent_lock.write();
                            Arc::clone(&parent.waitpid)
                        };

                        waitpid.send(pid, (sig << 8) | 0x7F);
                    } else {
                        println!("{}: {} not found for stop", pid.into(), ppid.into());
                    }
                }

                unsafe { switch() };
            },
            _ => {
                println!("Exit {}", sig);
                syscall::exit(sig);
            }
        }
    } else if handler == SIG_IGN {
        println!("Ignore");
    } else {
        println!("Call {:X}", handler);

        unsafe {
            let mut sp = ::USER_SIGSTACK_OFFSET + ::USER_SIGSTACK_SIZE - 256;

            sp = (sp / 16) * 16;

            sp -= mem::size_of::<usize>();
            *(sp as *mut usize) = restorer;

            usermode(handler, sp, sig);
        }
    }
}
