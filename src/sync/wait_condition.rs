use core::mem::ManuallyDrop;

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use crate::{
    context::{self, ContextLock, PreemptGuard},
    sync::{CleanLockToken, LockToken, Lower, Mutex, L1, L2, L3},
};

#[derive(Debug)]
pub struct WaitCondition {
    contexts: Mutex<L3, Vec<Weak<ContextLock>>>,
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

    /// Wait until notified. Unlocks guard when blocking is ready. Returns false if resumed by a signal or the notify_signal function.
    /// Wrapper to wait_setup -> drop(guard) -> context::switch -> wait_cleanup without currently holding lock for guard.
    pub fn wait<T>(&self, guard: T, reason: &'static str, token: &mut CleanLockToken) -> bool {
        let current_context_ref = context::current();
        {
            // Avoid a context switch between blocking ourselves and adding
            // ourselves to the wait list as otherwise we might miss a wakeup.
            // We cannot add ourselves to the wait list first as that would lead
            // to deadlock if we were woken up immediately.
            let mut preempt = PreemptGuard::new(&current_context_ref, token);
            let token = preempt.token();
            if !self.wait_setup(&current_context_ref, reason, token.token()) {
                return false;
            }

            drop(guard);
        }

        context::switch(token);

        self.wait_cleanup(&current_context_ref, token.token())
    }

    /// Enqueues the context and sets it to blocked.
    /// Returns true if successfully blocked, false if a signal is pending.
    pub fn wait_setup<'a, LP>(
        &self,
        current_context_ref: &Arc<ContextLock>,
        reason: &'static str,
        mut lock_token: LockToken<'a, LP>,
    ) -> bool
    where
        LP: Lower<L2>,
    {
        {
            let mut context = current_context_ref.write(LockToken::downgraded(lock_token.token()));
            if let Some((control, pctl, _)) = context.sigcontrol()
                && control.currently_pending_unblocked(pctl) != 0
            {
                return false;
            }
            context.block(reason);
        }

        self.contexts
            .lock(LockToken::downgraded(lock_token))
            .push(Arc::downgrade(current_context_ref));

        true
    }

    /// Cleans up the wait list after waking up.
    /// Returns true if we actually waited, false if we were removed by signal/notify_signal.
    pub fn wait_cleanup<'a, LP>(
        &self,
        current_context_ref: &Arc<ContextLock>,
        lock_token: LockToken<'a, LP>,
    ) -> bool
    where
        LP: Lower<L1>,
    {
        let mut waited = true;
        let mut contexts = self.contexts.lock(LockToken::downgraded(lock_token));

        // TODO: retain
        let mut i = 0;
        while i < contexts.len() {
            if Weak::as_ptr(&contexts[i]) == Arc::as_ptr(current_context_ref) {
                contexts.remove(i);
                waited = false;
                break;
            } else {
                i += 1;
            }
        }

        waited
    }

    pub fn into_drop(mut self, token: &mut CleanLockToken) {
        ManuallyDrop::new(self).inner_drop(token);
    }

    fn inner_drop(&mut self, token: &mut CleanLockToken) {
        unsafe {
            self.notify_signal(token);
        }
    }
}

impl Drop for WaitCondition {
    fn drop(&mut self) {
        //TODO: drop violates lock tokens
        let mut token = unsafe { CleanLockToken::new() };
        self.inner_drop(&mut token);
        #[cfg(feature = "drop_panic")]
        {
            panic!("WaitCondition dropped");
        }
    }
}
