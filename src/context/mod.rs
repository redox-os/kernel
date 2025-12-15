//! # Context management
//!
//! For resources on contexts, please consult [wikipedia](https://en.wikipedia.org/wiki/Context_switch) and  [osdev](https://wiki.osdev.org/Context_Switching)

use alloc::{collections::BTreeSet, sync::Arc};
use core::num::NonZeroUsize;

use crate::{
    context::memory::AddrSpaceWrapper,
    cpu_set::LogicalCpuSet,
    paging::{RmmA, RmmArch, TableKind},
    percpu::PercpuBlock,
    sync::{
        ArcRwLockWriteGuard, CleanLockToken, LockToken, RwLock, RwLockReadGuard, RwLockWriteGuard,
        L0, L1, L2,
    },
    syscall::error::Result,
};

use self::context::Kstack;
pub use self::{
    context::{BorrowedHtBuf, Context, Status},
    switch::switch,
};

pub type ContextLock = RwLock<L2, Context>;
pub type ArcContextLockWriteGuard = ArcRwLockWriteGuard<L2, Context>;

#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64.rs"]
mod arch;

#[cfg(target_arch = "x86")]
#[path = "arch/x86.rs"]
mod arch;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
mod arch;

#[cfg(target_arch = "riscv64")]
#[path = "arch/riscv64.rs"]
mod arch;

/// Context struct
pub mod context;

/// Context switch function
pub mod switch;

/// File struct - defines a scheme and a file number
pub mod file;

/// Memory struct - contains a set of pages for a context
pub mod memory;

/// Signal handling
pub mod signal;

/// Timeout handling
pub mod timeout;

pub use self::switch::switch_finish_hook;

/// Maximum context files
pub const CONTEXT_MAX_FILES: usize = 65_536;

pub use self::arch::empty_cr3;

// Set of weak references to all contexts available for scheduling. The only strong references are
// the context file descriptors.
static CONTEXTS: RwLock<L1, BTreeSet<ContextRef>> = RwLock::new(BTreeSet::new());

/// Get the global schemes list, const
pub fn contexts(token: LockToken<'_, L0>) -> RwLockReadGuard<'_, L1, BTreeSet<ContextRef>> {
    CONTEXTS.read(token)
}

/// Get the global schemes list, mutable
pub fn contexts_mut(token: LockToken<'_, L0>) -> RwLockWriteGuard<'_, L1, BTreeSet<ContextRef>> {
    CONTEXTS.write(token)
}

pub fn init(token: &mut CleanLockToken) {
    let owner = None; // kmain not owned by any fd
    let mut context = Context::new(owner).expect("failed to create kmain context");
    context.sched_affinity = LogicalCpuSet::empty();
    context.sched_affinity.atomic_set(crate::cpu_id());

    context.name.clear();
    context.name.push_str("[kmain]");

    self::arch::EMPTY_CR3.call_once(|| unsafe { RmmA::table(TableKind::User) });

    context.status = Status::Runnable;
    context.running = true;
    context.cpu_id = Some(crate::cpu_id());

    let context_lock = Arc::new(ContextLock::new(context));

    contexts_mut(token.token()).insert(ContextRef(Arc::clone(&context_lock)));

    unsafe {
        let percpu = PercpuBlock::current();
        percpu
            .switch_internals
            .set_current_context(Arc::clone(&context_lock));
        percpu.switch_internals.set_idle_context(context_lock);
    }
}

pub fn current() -> Arc<ContextLock> {
    PercpuBlock::current()
        .switch_internals
        .with_context(Arc::clone)
}
pub fn try_current() -> Option<Arc<ContextLock>> {
    PercpuBlock::current()
        .switch_internals
        .try_with_context(|context| context.map(Arc::clone))
}
pub fn is_current(context: &Arc<ContextLock>) -> bool {
    PercpuBlock::current()
        .switch_internals
        .with_context(|current| Arc::ptr_eq(context, current))
}

pub struct ContextRef(pub Arc<ContextLock>);
impl ContextRef {
    pub fn upgrade(&self) -> Option<Arc<ContextLock>> {
        Some(Arc::clone(&self.0))
    }
}

impl Ord for ContextRef {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        Ord::cmp(&Arc::as_ptr(&self.0), &Arc::as_ptr(&other.0))
    }
}
impl PartialOrd for ContextRef {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}
impl PartialEq for ContextRef {
    fn eq(&self, other: &Self) -> bool {
        Ord::cmp(self, other) == core::cmp::Ordering::Equal
    }
}
impl Eq for ContextRef {}

/// Spawn a context from a function.
pub fn spawn(
    userspace_allowed: bool,
    owner_proc_id: Option<NonZeroUsize>,
    func: extern "C" fn(),
    token: &mut CleanLockToken,
) -> Result<Arc<ContextLock>> {
    let stack = Kstack::new()?;

    let context_lock = Arc::new(ContextLock::new(Context::new(owner_proc_id)?));

    contexts_mut(token.token()).insert(ContextRef(Arc::clone(&context_lock)));

    {
        let mut context = context_lock.write(token.token());
        let _ = context.set_addr_space(Some(AddrSpaceWrapper::new()?));
        context
            .arch
            .setup_initial_call(&stack, func, userspace_allowed);

        context.kstack = Some(stack);
        context.userspace = userspace_allowed;
    }
    Ok(context_lock)
}

/// A guard that disables preemption for a context while it is alive.
///
/// This guard is used to ensure that a sequence of operations is atomic with respect to preemption.
/// It automatically re-enables preemption when dropped.
///
/// Because the guard must hold a mutable reference to the `CleanLockToken` to re-enable preemption
/// in `Drop`, it consumes the token. The `token()` method allows re-borrowing the token for use
/// within the guard's scope.
pub struct PreemptGuard<'a> {
    context: &'a ContextLock,
    token: &'a mut CleanLockToken,
}

impl<'a> PreemptGuard<'a> {
    pub fn new(context: &'a ContextLock, token: &'a mut CleanLockToken) -> PreemptGuard<'a> {
        context.write(token.token()).preempt_locks += 1;
        PreemptGuard { context, token }
    }

    /// Get a mutable reference to the underlying `CleanLockToken`.
    ///
    /// This is necessary because the `PreemptGuard` owns the mutable reference to the token
    /// (to use it in `Drop`), so we cannot use the original `token` variable while the guard exists.
    pub fn token(&mut self) -> &mut CleanLockToken {
        self.token
    }
}

impl Drop for PreemptGuard<'_> {
    fn drop(&mut self) {
        self.context.write(self.token.token()).preempt_locks -= 1;
    }
}
