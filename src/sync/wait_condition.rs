use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use crate::{
    context::{self, ContextLock, PreemptGuard},
    sync::{CleanLockToken, L1, Mutex},
};

#[derive(Debug)]
pub struct WaitCondition {
    contexts: Mutex<L1, Vec<Weak<ContextLock>>>,
}

impl WaitCondition {
    pub const fn new() -> WaitCondition {
        WaitCondition {
            contexts: Mutex::new(Vec::new()),
        }
    }

    // Notify all waiters
    pub fn notify(&self, token: &mut CleanLockToken) -> usize {
        let mut contexts = self.contexts.lock(token.token());
        let (contexts, mut token) = contexts.token_split();
        let len = contexts.len();
        while let Some(context_weak) = contexts.pop() {
            if let Some(context_ref) = context_weak.upgrade() {
                context_ref.write(token.token()).unblock();
            }
        }
        len
    }

    // Notify as though a signal woke the waiters
    pub unsafe fn notify_signal(&self, token: &mut CleanLockToken) -> usize {
        let mut contexts = self.contexts.lock(token.token());
        let (contexts, mut token) = contexts.token_split();
        let len = contexts.len();
        for context_weak in contexts.iter() {
            if let Some(context_ref) = context_weak.upgrade() {
                context_ref.write(token.token()).unblock();
            }
        }
        len
    }

    // Wait until notified. Unlocks guard when blocking is ready. Returns false if resumed by a signal or the notify_signal function
    pub fn wait<T>(&self, guard: T, reason: &'static str, token: &mut CleanLockToken) -> bool {
        let current_context_ref = context::current();
        {
            // Avoid a context switch between blocking ourselves and adding
            // ourselves to the wait list as otherwise we might miss a wakeup.
            // We cannot add ourselves to the wait list first as that would lead
            // to deadlock if we were woken up immediately.
            let mut preempt = PreemptGuard::new(&current_context_ref, token);
            let token = preempt.token();
            {
                let mut context = current_context_ref.write(token.token());
                if let Some((control, pctl, _)) = context.sigcontrol()
                    && control.currently_pending_unblocked(pctl) != 0
                {
                    return false;
                }
                context.block(reason);
            }

            self.contexts
                .lock(token.token())
                .push(Arc::downgrade(&current_context_ref));

            drop(guard);
        }

        context::switch(token);

        let mut waited = true;

        {
            let mut contexts = self.contexts.lock(token.token());

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
        //TODO: drop violates lock tokens
        unsafe {
            let mut token = CleanLockToken::new();
            self.notify_signal(&mut token);
        };
    }
}
