use core::mem;
use core::sync::atomic::Ordering;
use context::{arch, contexts, Context, Status, CONTEXT_ID};
use start::usermode;
use syscall::flag::{SIG_DFL, SIG_IGN, SIGCHLD, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU};

use gdt;
use interrupt;
use interrupt::irq::PIT_TICKS;
use syscall;
use time;

/// Switch to the next context
///
/// # Safety
///
/// Do not call this while holding locks!
pub unsafe fn switch() -> bool {
    use core::ops::DerefMut;

    //set PIT Interrupt counter to 0, giving each process same amount of PIT ticks
    PIT_TICKS.store(0, Ordering::SeqCst);

    // Set the global lock to avoid the unsafe operations below from causing issues
    while arch::CONTEXT_SWITCH_LOCK.compare_and_swap(false, true, Ordering::SeqCst) {
        interrupt::pause();
    }

    let cpu_id = ::cpu_id();

    let from_ptr;
    let mut to_ptr = 0 as *mut Context;
    let mut to_sig = None;
    {
        let contexts = contexts();
        {
            let context_lock = contexts
                .current()
                .expect("context::switch: not inside of context");
            let mut context = context_lock.write();
            from_ptr = context.deref_mut() as *mut Context;
        }

        let check_context = |context: &mut Context| -> bool {
            // Take ownership if not already owned
            if context.cpu_id == None {
                context.cpu_id = Some(cpu_id);
                // println!("{}: take {} {}", cpu_id, context.id, ::core::str::from_utf8_unchecked(&context.name.lock()));
            }

            // Restore from signal
            if context.ksig_restore {
                let ksig = context.ksig.take().expect("context::switch: ksig not set with ksig_restore");
                context.arch = ksig.0;
                if let Some(ref mut kfx) = context.kfx {
                    kfx.clone_from_slice(&ksig.1.expect("context::switch: ksig kfx not set with ksig_restore"));
                } else {
                    panic!("context::switch: kfx not set with ksig_restore");
                }
                if let Some(ref mut kstack) = context.kstack {
                    kstack.clone_from_slice(&ksig.2.expect("context::switch: ksig kstack not set with ksig_restore"));
                } else {
                    panic!("context::switch: kstack not set with ksig_restore");
                }
                context.ksig_restore = false;

                context.unblock();
            }

            // Unblock when there are pending signals
            if context.status == Status::Blocked && !context.pending.is_empty() {
                context.unblock();
            }

            // Wake from sleep
            if context.status == Status::Blocked && context.wake.is_some() {
                let wake = context.wake.expect("context::switch: wake not set");

                let current = time::monotonic();
                if current.0 > wake.0 || (current.0 == wake.0 && current.1 >= wake.1) {
                    context.wake = None;
                    context.unblock();
                }
            }

            // Switch to context if it needs to run, is not currently running, and is owned by the current CPU
            !context.running && context.status == Status::Runnable && context.cpu_id == Some(cpu_id)
        };

        for (pid, context_lock) in contexts.iter() {
            if *pid > (*from_ptr).id {
                let mut context = context_lock.write();
                if check_context(&mut context) {
                    to_ptr = context.deref_mut() as *mut Context;
                    if (&mut *to_ptr).ksig.is_none() {
                        to_sig = context.pending.pop_front();
                    }
                    break;
                }
            }
        }

        if to_ptr as usize == 0 {
            for (pid, context_lock) in contexts.iter() {
                if *pid < (*from_ptr).id {
                    let mut context = context_lock.write();
                    if check_context(&mut context) {
                        to_ptr = context.deref_mut() as *mut Context;
                        if (&mut *to_ptr).ksig.is_none() {
                            to_sig = context.pending.pop_front();
                        }
                        break;
                    }
                }
            }
        }
    };

    // Switch process states, TSS stack pointer, and store new context ID
    if to_ptr as usize != 0 {
        (&mut *from_ptr).running = false;
        (&mut *to_ptr).running = true;
        if let Some(ref stack) = (*to_ptr).kstack {
            gdt::TSS.rsp[0] = (stack.as_ptr() as usize + stack.len() - 256) as u64;
        }
        CONTEXT_ID.store((&mut *to_ptr).id, Ordering::SeqCst);
    }

    // Unset global lock before switch, as arch is only usable by the current CPU at this time
    arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);

    if to_ptr as usize == 0 {
        // No target was found, return

        false
    } else {
        if let Some(sig) = to_sig {
            // Signal was found, run signal handler

            //TODO: Allow nested signals
            assert!((&mut *to_ptr).ksig.is_none());

            let arch = (&mut *to_ptr).arch.clone();
            let kfx = (&mut *to_ptr).kfx.clone();
            let kstack = (&mut *to_ptr).kstack.clone();
            (&mut *to_ptr).ksig = Some((arch, kfx, kstack));
            (&mut *to_ptr).arch.signal_stack(signal_handler, sig);
        }

        (&mut *from_ptr).arch.switch_to(&mut (&mut *to_ptr).arch);

        true
    }
}

extern "C" fn signal_handler(sig: usize) {
    let (action, restorer) = {
        let contexts = contexts();
        let context_lock = contexts.current().expect("context::signal_handler not inside of context");
        let context = context_lock.read();
        let actions = context.actions.lock();
        actions[sig]
    };

    let handler = action.sa_handler as usize;
    println!("Handler {}: {:X}", sig, handler);
    if handler == SIG_DFL {
        match sig {
            SIGCHLD => {
                println!("SIGCHLD");
            },
            SIGCONT => {
                println!("Continue");

                let contexts = contexts();
                let context_lock = contexts.current().expect("context::signal_handler not inside of context");
                let mut context = context_lock.write();
                if context.stopped {
                    context.stopped = false;
                    context.unblock();
                }
            },
            SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => {
                println!("Stop");

                let contexts = contexts();
                let context_lock = contexts.current().expect("context::signal_handler not inside of context");
                let mut context = context_lock.write();
                if ! context.stopped {
                    context.stopped = true;
                    context.block();
                }
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
