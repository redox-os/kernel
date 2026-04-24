use core::mem::ManuallyDrop;

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use lfll::{List, LockFreeDequeList};

use crate::{
    context::{self, ContextLock, PreemptGuardL2},
    sync::{CleanLockToken, LockToken, Mutex, L1, L2, L3},
};

#[derive(Debug)]
pub struct WaitCondition {
    contexts: LockFreeDequeList<Weak<ContextLock>>,
}

impl WaitCondition {
    pub const fn new() -> WaitCondition {
        WaitCondition {
            contexts: LockFreeDequeList::new(),
        }
    }

    // Notify all waiters
    pub fn notify(&self, token: &mut CleanLockToken) -> usize {
        self.notify_locked(token.token().downgrade())
    }

    pub fn notify_locked(&self, mut token: LockToken<'_, L1>) -> usize {
        let contexts = &self.contexts;
        let mut len = 0;
        while let Some((_, context_weak)) = contexts.pop_front() {
            if let Some(context_ref) = context_weak.upgrade() {
                context_ref.write(token.token()).unblock();
            }
            len += 1;
        }
        len
    }

    // Notify as though a signal woke the waiters
    pub unsafe fn notify_signal(&self, mut token: LockToken<'_, L1>) -> usize {
        let contexts = &self.contexts;
        let mut len = 0;
        for (_, context_weak) in contexts.iter() {
            if let Some(context_ref) = context_weak.upgrade() {
                context_ref.write(token.token()).unblock();
            }
            len += 1;
        }
        len
    }

    /// Wait until notified. Unlocks guard when blocking is ready. Returns false if resumed by a signal or the notify_signal function.
    /// SAFETY: Caller MUST ensure the given token is coming from the guard. There is no compiler check to do it.
    pub fn wait<'a, T>(
        &self,
        guard: T,
        reason: &'static str,
        token: &'a mut LockToken<'a, L1>,
    ) -> bool {
        let mut token = token.downgrade();
        self.wait_inner(guard, reason, &mut token)
    }

    pub fn wait_inner<'a, T>(
        &self,
        guard: T,
        reason: &'static str,
        token: &'a mut LockToken<'a, L2>,
    ) -> bool {
        let current_context_ref = context::current();
        {
            // Avoid a context switch between blocking ourselves and adding
            // ourselves to the wait list as otherwise we might miss a wakeup.
            // We cannot add ourselves to the wait list first as that would lead
            // to deadlock if we were woken up immediately.
            let mut token = token.token();
            let mut preempt = PreemptGuardL2::new(&current_context_ref, &mut token);
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
                .push_back(Arc::downgrade(&current_context_ref));

            drop(guard);
        }

        {
            // SAFETY: Guaranteed by caller
            let token = unsafe { &mut CleanLockToken::new() };
            context::switch(token);
        }

        let mut waited = true;

        {
            let contexts = &self.contexts;

            if let Some((index, _)) = contexts
                .iter()
                .find(|(_, c)| Weak::as_ptr(c) == Arc::as_ptr(&current_context_ref))
            {
                contexts.delete(index);
                waited = false;
            }
        }

        waited
    }

    pub fn into_drop(self, token: &mut CleanLockToken) {
        self.into_drop_locked(token.token().downgrade());
    }

    pub fn into_drop_locked(self, token: LockToken<'_, L1>) {
        ManuallyDrop::new(self).inner_drop(token);
    }

    fn inner_drop(&mut self, token: LockToken<'_, L1>) {
        unsafe {
            self.notify_signal(token);
        }
    }
}

impl Drop for WaitCondition {
    fn drop(&mut self) {
        //TODO: drop violates lock tokens
        let mut token = unsafe { CleanLockToken::new() };
        self.inner_drop(token.downgrade());
        #[cfg(feature = "drop_panic")]
        {
            panic!("WaitCondition dropped");
        }
    }
}
