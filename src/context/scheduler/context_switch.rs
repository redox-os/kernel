use core::cell::{Cell, RefCell};

use alloc::sync::Arc;
use spinning_top::{guard::ArcRwSpinlockWriteGuard, RwSpinlock};

use crate::context::Context;

pub enum UpdateResult {
    CanSwitch,
    Skip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchResult {
    Switched,
    AllContextsIdle,
}

pub struct SwitchResultInner {
    pub _prev_guard: ArcRwSpinlockWriteGuard<Context>,
    pub _next_guard: ArcRwSpinlockWriteGuard<Context>,
}

/// Holds per-CPU state necessary for context switching.
///
/// This struct contains information such as the idle context, current context, and PIT tick counts,
/// as well as fields required for managing ptrace sessions and signals.
#[derive(Default)]
pub struct ContextSwitchPercpu {
    pub(super) switch_result: Cell<Option<SwitchResultInner>>,
    pub(super) pit_ticks: Cell<usize>,

    current_ctxt: RefCell<Option<Arc<RwSpinlock<Context>>>>,

    /// The idle process.
    idle_ctxt: RefCell<Option<Arc<RwSpinlock<Context>>>>,

    pub(crate) being_sigkilled: Cell<bool>,
}

impl ContextSwitchPercpu {
    /// Applies a function to the current context, allowing controlled access.
    ///
    /// # Parameters
    /// - `f`: A closure that receives a reference to the current context and returns a value.
    ///
    /// # Returns
    /// The result of applying `f` to the current context.
    pub fn with_context<T>(&self, f: impl FnOnce(&Arc<RwSpinlock<Context>>) -> T) -> T {
        f(&*self
            .current_ctxt
            .borrow()
            .as_ref()
            .expect("not inside of context"))
    }

    /// Sets the current context to a new value.
    ///
    /// # Safety
    /// This function is unsafe as it modifies the context state directly.
    ///
    /// # Parameters
    /// - `new`: The new context to be set as the current context.
    pub unsafe fn set_current_context(&self, new: Arc<RwSpinlock<Context>>) {
        *self.current_ctxt.borrow_mut() = Some(new);
    }

    /// Sets the idle context to a new value.
    ///
    /// # Safety
    /// This function is unsafe as it modifies the idle context state directly.
    ///
    /// # Parameters
    /// - `new`: The new context to be set as the idle context.
    pub unsafe fn set_idle_context(&self, new: Arc<RwSpinlock<Context>>) {
        *self.idle_ctxt.borrow_mut() = Some(new);
    }

    /// Retrieves the current idle context.
    ///
    /// # Returns
    /// A reference to the idle context.
    pub fn idle_context(&self) -> Arc<RwSpinlock<Context>> {
        Arc::clone(
            self.idle_ctxt
                .borrow()
                .as_ref()
                .expect("no idle context present"),
        )
    }
}
