use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use spin::Mutex;
use spinning_top::RwSpinlock;

use crate::context::{
    self,
    scheduler::{context_join, context_leave},
    Context, ContextRef,
};

#[derive(Debug)]
pub struct WaitCondition {
    contexts: Mutex<Vec<Weak<RwSpinlock<Context>>>>,
}

impl WaitCondition {
    pub const fn new() -> WaitCondition {
        WaitCondition {
            contexts: Mutex::new(Vec::new()),
        }
    }

    // Notify all waiters
    pub fn notify(&self) -> usize {
        let mut contexts = self.contexts.lock();
        let len = contexts.len();
        while let Some(context_weak) = contexts.pop() {
            if let Some(context_ref) = context_weak.upgrade() {
                let unblocked = context_ref.write().unblock();
                if cfg!(feature = "scheduler_eevdf") && unblocked {
                    context_join(
                        &mut context_ref.write(),
                        ContextRef(Arc::clone(&context_ref)),
                    );
                }
            }
        }
        len
    }

    // Notify as though a signal woke the waiters
    pub unsafe fn notify_signal(&self) -> usize {
        let contexts = self.contexts.lock();
        let len = contexts.len();
        for context_weak in contexts.iter() {
            if let Some(context_ref) = context_weak.upgrade() {
                let unblocked = context_ref.write().unblock();
                if cfg!(feature = "scheduler_eevdf") && unblocked {
                    context_join(
                        &mut context_ref.write(),
                        ContextRef(Arc::clone(&context_ref)),
                    );
                }
            }
        }
        len
    }

    // Wait until notified. Unlocks guard when blocking is ready. Returns false if resumed by a signal or the notify_signal function
    pub fn wait<T>(&self, guard: T, reason: &'static str) -> bool {
        let current_context_ref = context::current();
        {
            {
                let mut context = current_context_ref.write();
                if let Some((control, pctl, _)) = context.sigcontrol()
                    && control.currently_pending_unblocked(pctl) != 0
                {
                    return false;
                }
                let was_runnable = context.block(reason);
                if cfg!(feature = "scheduler_eevdf") && was_runnable {
                    context_leave(&mut context, ContextRef(Arc::clone(&current_context_ref)))
                }
            }

            self.contexts
                .lock()
                .push(Arc::downgrade(&current_context_ref));

            drop(guard);
        }

        context::switch();

        let mut waited = true;

        {
            let mut contexts = self.contexts.lock();

            // TODO: retain
            let mut i = 0;
            while i < contexts.len() {
                if Weak::as_ptr(&contexts[i]) == Arc::as_ptr(&current_context_ref) {
                    contexts.remove(i);
                    waited = false;
                    break;
                } else {
                    i += 1;
                }
            }
        }

        waited
    }
}

impl Drop for WaitCondition {
    fn drop(&mut self) {
        unsafe { self.notify_signal() };
    }
}
