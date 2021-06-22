use core::cell::Cell;
use core::ops::Bound;
use core::sync::atomic::Ordering;

use alloc::sync::Arc;

use spin::RwLock;

use crate::context::signal::signal_handler;
use crate::context::{arch, contexts, Context, Status, CONTEXT_ID};
#[cfg(target_arch = "x86_64")]
use crate::gdt;
use crate::interrupt::irq::PIT_TICKS;
use crate::interrupt;
use crate::ptrace;
use crate::time;

unsafe fn update(context: &mut Context, cpu_id: usize) {
    // Take ownership if not already owned
    if context.cpu_id == None {
        context.cpu_id = Some(cpu_id);
        // println!("{}: take {} {}", cpu_id, context.id, *context.name.read());
    }

    // Restore from signal, must only be done from another context to avoid overwriting the stack!
    if context.ksig_restore && ! context.running {
        let was_singlestep = ptrace::regs_for(context).map(|s| s.is_singlestep()).unwrap_or(false);

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

        // Keep singlestep flag across jumps
        if let Some(regs) = ptrace::regs_for_mut(context) {
            regs.set_singlestep(was_singlestep);
        }

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
}

struct SwitchResult {
    prev_lock: Arc<RwLock<Context>>,
    next_lock: Arc<RwLock<Context>>,
}

pub unsafe extern "C" fn switch_finish_hook() {
    if let Some(SwitchResult { prev_lock, next_lock }) = SWITCH_RESULT.take() {
        prev_lock.force_write_unlock();
        next_lock.force_write_unlock();
    } else {
        // TODO: unreachable_unchecked()?
        core::intrinsics::abort();
    }
    arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);
}

#[thread_local]
static SWITCH_RESULT: Cell<Option<SwitchResult>> = Cell::new(None);

unsafe fn runnable(context: &Context, cpu_id: usize) -> bool {
    // Switch to context if it needs to run, is not currently running, and is owned by the current CPU
    !context.running && !context.ptrace_stop && context.status == Status::Runnable && context.cpu_id == Some(cpu_id)
}

/// Switch to the next context
///
/// # Safety
///
/// Do not call this while holding locks!
pub unsafe fn switch() -> bool {
    // TODO: Better memory orderings?
    //set PIT Interrupt counter to 0, giving each process same amount of PIT ticks
    let ticks = PIT_TICKS.swap(0, Ordering::SeqCst);

    // Set the global lock to avoid the unsafe operations below from causing issues
    while arch::CONTEXT_SWITCH_LOCK.compare_exchange_weak(false, true, Ordering::SeqCst, Ordering::Relaxed).is_err() {
        interrupt::pause();
    }

    let cpu_id = crate::cpu_id();

    let from_context_lock;
    let mut from_context_guard;
    let mut to_context_lock: Option<(Arc<spin::RwLock<Context>>, *mut Context)> = None;
    let mut to_sig = None;
    {
        let contexts = contexts();
        {
            from_context_lock = Arc::clone(contexts
                .current()
                .expect("context::switch: not inside of context"));
            from_context_guard = from_context_lock.write();
            from_context_guard.ticks += ticks as u64 + 1; // Always round ticks up
        }

        for (pid, context_lock) in contexts.iter() {
            let mut context;
            let context_ref = if *pid == from_context_guard.id {
                &mut *from_context_guard
            } else {
                context = context_lock.write();
                &mut *context
            };
            update(context_ref, cpu_id);
        }

        for (_pid, context_lock) in contexts
            // Include all contexts with IDs greater than the current...
            .range(
                (Bound::Excluded(from_context_guard.id), Bound::Unbounded)
            )
            .chain(contexts
                // ... and all contexts with IDs less than the current...
                .range((Bound::Unbounded, Bound::Excluded(from_context_guard.id)))
            )
            // ... but not the current context, which is already locked
        {
            let context_lock = Arc::clone(context_lock);
            let mut to_context_guard = context_lock.write();

            if runnable(&*to_context_guard, cpu_id) {
                if to_context_guard.ksig.is_none() {
                    to_sig = to_context_guard.pending.pop_front();
                }
                let ptr: *mut Context = &mut *to_context_guard;
                core::mem::forget(to_context_guard);
                to_context_lock = Some((context_lock, ptr));
                break;
            } else {
                continue;
            }
        }
    };

    // Switch process states, TSS stack pointer, and store new context ID
    if let Some((to_context_lock, to_ptr)) = to_context_lock {
        let to_context: &mut Context = &mut *to_ptr;

        from_context_guard.running = false;
        to_context.running = true;
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(ref stack) = to_context.kstack {
                gdt::set_tss_stack(stack.as_ptr() as usize + stack.len());
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            let pid = to_context.id.into();
            to_context.arch.set_tcb(pid);
        }
        CONTEXT_ID.store(to_context.id, Ordering::SeqCst);

        if let Some(sig) = to_sig {
            // Signal was found, run signal handler

            //TODO: Allow nested signals
            assert!(to_context.ksig.is_none());

            let arch = to_context.arch.clone();
            let kfx = to_context.kfx.clone();
            let kstack = to_context.kstack.clone();
            to_context.ksig = Some((arch, kfx, kstack, sig));
            to_context.arch.signal_stack(signal_handler, sig);
        }

        let from_arch_ptr: *mut arch::Context = &mut from_context_guard.arch;
        core::mem::forget(from_context_guard);

        let prev_arch: &mut arch::Context = &mut *from_arch_ptr;
        let next_arch: &mut arch::Context = &mut to_context.arch;

        // to_context_guard only exists as a raw pointer, but is still locked

        SWITCH_RESULT.set(Some(SwitchResult {
            prev_lock: from_context_lock,
            next_lock: to_context_lock,
        }));

        arch::switch_to(prev_arch, next_arch);

        // NOTE: After switch_to is called, the return address can even be different from the
        // current return address, meaning that we cannot use local variables here, and that we
        // need to use the `switch_finish_hook` to be able to release the locks.

        true
    } else {
        // No target was found, unset global lock and return
        arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);

        false
    }
}
