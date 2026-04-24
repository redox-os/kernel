//! # Context management
//!
//! For resources on contexts, please consult [wikipedia](https://en.wikipedia.org/wiki/Context_switch) and  [osdev](https://wiki.osdev.org/Context_Switching)

use alloc::sync::Arc;
use core::{
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};
use lfll::{List, LockFreeDequeList};

use crate::{
    context::memory::AddrSpaceWrapper,
    cpu_set::LogicalCpuSet,
    memory::{RmmA, RmmArch, TableKind},
    percpu::PercpuBlock,
    sync::{ArcRwLockWriteGuard, CleanLockToken, LockToken, RwLock, L0, L1, L2, L4},
    syscall::error::Result,
};

use self::context::Kstack;
pub use self::{
    context::{BorrowedHtBuf, Context, Status},
    switch::switch,
};

pub type ContextLock = RwLock<L4, Context>;
pub type ArcContextLockWriteGuard = ArcRwLockWriteGuard<L4, Context>;

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
static CONTEXTS: LockFreeDequeList<ContextRef> = LockFreeDequeList::new();

// Actual context store for the scheduler
static RUN_CONTEXTS: RunContextData = RunContextData::new();

const PRIO_CAP: usize = 40;

pub struct RunContextData {
    set: [LockFreeDequeList<ContextRef>; PRIO_CAP],
    len: [AtomicUsize; PRIO_CAP],
}

impl RunContextData {
    pub const fn new() -> Self {
        const EMPTY_VEC: LockFreeDequeList<ContextRef> = LockFreeDequeList::new();
        const EMPTY_LEN: AtomicUsize = AtomicUsize::new(0);
        Self {
            set: [EMPTY_VEC; PRIO_CAP],
            len: [EMPTY_LEN; PRIO_CAP],
        }
    }
    pub fn push_back(&self, prio: usize, ctx: ContextRef) {
        self.len[prio].fetch_add(1, Ordering::Relaxed);
        self.set[prio].push_back(ctx);
    }
    pub fn pop_front(&self, prio: usize) -> Option<&ContextRef> {
        self.len[prio].fetch_sub(1, Ordering::Relaxed);
        self.set[prio].pop_front().map(|x| x.1)
    }
    pub fn total(&self) -> usize {
        let mut sum = 0;
        for i in 0..PRIO_CAP {
            sum += self.len[i].load(Ordering::Relaxed);
        }
        sum
    }
}

/// Get the global schemes list
pub fn contexts() -> &'static LockFreeDequeList<ContextRef> {
    &CONTEXTS
}

pub fn run_contexts() -> &'static RunContextData {
    &RUN_CONTEXTS
}

pub fn init(_token: &mut CleanLockToken) {
    let id = crate::cpu_id();

    let owner = None; // kmain not owned by any fd
    let context_id = contexts().reserve_back();
    let mut context = Context::new(owner, context_id).expect("failed to create kmain context");
    context.sched_affinity = LogicalCpuSet::empty();
    context.sched_affinity.atomic_set(crate::cpu_id());

    context.name.clear();
    context.name.push_str("[kmain]");

    self::arch::EMPTY_CR3.call_once(|| RmmA::table(TableKind::User));

    context.status = Status::Runnable;
    context.running = true;
    context.cpu_id = Some(crate::cpu_id());
    context.enqueued = false;

    let priority = context.prio;

    let context_lock = Arc::new(ContextLock::new(context));

    // Set this as current context and idle context, but don't treat it as regular context queue
    unsafe {
        let percpu = PercpuBlock::current();
        percpu
            .switch_internals
            .set_current_context(Arc::clone(&context_lock));
        percpu.switch_internals.set_idle_context(context_lock);
    }
}

pub fn wakeup_context(context_lock: &Arc<RwLock<L4, Context>>, mut token: LockToken<L0>) {
    let priority = {
        let mut context = context_lock.write(token.token());

        context.wake = None;
        context.unblock();

        if !(context.status.is_runnable() && !context.running && !context.enqueued) {
            return;
        }

        context.enqueued = true;

        context.prio
    };

    run_contexts().push_back(priority, ContextRef(Arc::clone(context_lock)));
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

#[derive(Clone)]
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

    let context_id = contexts().reserve_back();
    let mut context = Context::new(owner_proc_id, context_id)?;

    let _ = context.set_addr_space(Some(AddrSpaceWrapper::new()?), token.downgrade());
    context
        .arch
        .setup_initial_call(&stack, func, userspace_allowed);

    context.kstack = Some(stack);
    context.userspace = userspace_allowed;

    let context_lock = Arc::new(ContextLock::new(context));
    let context_ref = ContextRef(Arc::clone(&context_lock));

    let run_ref = ContextRef(Arc::clone(&context_lock));
    run_contexts().push_back(20, run_ref);
    contexts().push_back_reserved(context_ref, context_id);
    context_lock.write(token.token()).enqueued = true;

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

/// Variant of PreemptGuard behind a one-level token
pub struct PreemptGuardL1<'a> {
    context: &'a ContextLock,
    token: &'a mut LockToken<'a, L1>,
}

impl<'a> PreemptGuardL1<'a> {
    pub fn new(context: &'a ContextLock, token: &'a mut LockToken<'a, L1>) -> PreemptGuardL1<'a> {
        context.write(token.token()).preempt_locks += 1;
        PreemptGuardL1 { context, token }
    }

    /// Get a mutable reference to the underlying `LockToken<L1>`.
    pub fn token(&mut self) -> &mut LockToken<'a, L1> {
        self.token
    }
}

impl Drop for PreemptGuardL1<'_> {
    fn drop(&mut self) {
        self.context.write(self.token.token()).preempt_locks -= 1;
    }
}

/// Variant of PreemptGuard behind a one-level token
pub struct PreemptGuardL2<'a> {
    context: &'a ContextLock,
    token: &'a mut LockToken<'a, L2>,
}

impl<'a> PreemptGuardL2<'a> {
    pub fn new(context: &'a ContextLock, token: &'a mut LockToken<'a, L2>) -> PreemptGuardL2<'a> {
        context.write(token.token()).preempt_locks += 1;
        PreemptGuardL2 { context, token }
    }

    /// Get a mutable reference to the underlying `LockToken<L2>`.
    pub fn token(&mut self) -> &mut LockToken<'a, L2> {
        self.token
    }
}

impl Drop for PreemptGuardL2<'_> {
    fn drop(&mut self) {
        self.context.write(self.token.token()).preempt_locks -= 1;
    }
}
