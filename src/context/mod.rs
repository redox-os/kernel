//! # Context management
//!
//! For resources on contexts, please consult [wikipedia](https://en.wikipedia.org/wiki/Context_switch) and  [osdev](https://wiki.osdev.org/Context_Switching)

use alloc::{
    collections::{BTreeSet, VecDeque},
    sync::{Arc, Weak},
};
use core::{num::NonZeroUsize, ops::Deref};

use crate::{
    context::memory::AddrSpaceWrapper,
    cpu_set::LogicalCpuSet,
    memory::{RmmA, RmmArch, TableKind},
    percpu::PercpuBlock,
    sync::{
        ArcRwLockWriteGuard, CleanLockToken, LockToken, Mutex, MutexGuard, RwLock, RwLockReadGuard,
        RwLockWriteGuard, L0, L1, L2, L4,
    },
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
static CONTEXTS: RwLock<L2, BTreeSet<ContextRef>> = RwLock::new(BTreeSet::new());

// Actual context store for the scheduler
static RUN_CONTEXTS: Mutex<L1, RunContextData> = Mutex::new(RunContextData::new());

// Context that has been pushed out from RUN_CONTEXTS after being idle
static IDLE_CONTEXTS: Mutex<L2, VecDeque<WeakContextRef>> = Mutex::new(VecDeque::new());

pub struct RunContextData {
    set: [VecDeque<WeakContextRef>; 40],
}

impl RunContextData {
    pub const fn new() -> Self {
        const EMPTY_VEC: VecDeque<WeakContextRef> = VecDeque::new();
        Self {
            set: [EMPTY_VEC; 40],
        }
    }
}

/// Get the global schemes list, const
pub fn contexts(token: LockToken<'_, L1>) -> RwLockReadGuard<'_, L2, BTreeSet<ContextRef>> {
    CONTEXTS.read(token)
}

/// Get per cpu contexts, mutable
pub fn contexts_mut(token: LockToken<'_, L1>) -> RwLockWriteGuard<'_, L2, BTreeSet<ContextRef>> {
    CONTEXTS.write(token)
}

pub fn idle_contexts(token: LockToken<'_, L1>) -> MutexGuard<'_, L2, VecDeque<WeakContextRef>> {
    IDLE_CONTEXTS.lock(token)
}

pub fn idle_contexts_try(
    token: LockToken<'_, L1>,
) -> Option<MutexGuard<'_, L2, VecDeque<WeakContextRef>>> {
    IDLE_CONTEXTS.try_lock(token)
}

pub fn run_contexts(token: LockToken<'_, L0>) -> MutexGuard<'_, L1, RunContextData> {
    RUN_CONTEXTS.lock(token)
}

pub fn init(token: &mut CleanLockToken) {
    let owner = None; // kmain not owned by any fd
    let mut context = Context::new(owner).expect("failed to create kmain context");
    context.sched_affinity = LogicalCpuSet::empty();
    context.sched_affinity.atomic_set(crate::cpu_id());

    context.name.clear();
    context.name.push_str("[kmain]");

    self::arch::EMPTY_CR3.call_once(|| RmmA::table(TableKind::User));

    context.status = Status::Runnable;
    context.running = true;
    context.cpu_id = Some(crate::cpu_id());

    let priority = context.prio;

    let context_lock = Arc::new(ContextLock::new(context));

    let context_ref = ContextRef(Arc::clone(&context_lock));
    contexts_mut(token.token().downgrade()).insert(context_ref.clone());
    // Set this as current context and idle context, but don't treat it as regular context queue
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

#[derive(Clone)]
pub struct ContextRef(pub Arc<ContextLock>);
impl Deref for ContextRef {
    type Target = Arc<ContextLock>;
    fn deref(&self) -> &Self::Target {
        &self.0
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

#[derive(Clone)]
pub struct WeakContextRef(pub Weak<ContextLock>);
impl WeakContextRef {
    pub fn upgrade(&self) -> Option<Arc<ContextLock>> {
        self.0.upgrade()
    }
}

impl Ord for WeakContextRef {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        Ord::cmp(&Weak::as_ptr(&self.0), &Weak::as_ptr(&other.0))
    }
}
impl PartialOrd for WeakContextRef {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}
impl PartialEq for WeakContextRef {
    fn eq(&self, other: &Self) -> bool {
        Ord::cmp(self, other) == core::cmp::Ordering::Equal
    }
}
impl Eq for WeakContextRef {}

/// Spawn a context from a function.
pub fn spawn(
    userspace_allowed: bool,
    owner_proc_id: Option<NonZeroUsize>,
    func: extern "C" fn(),
    token: &mut CleanLockToken,
) -> Result<Arc<ContextLock>> {
    let stack = Kstack::new()?;

    let mut context = Context::new(owner_proc_id)?;

    let _ = context.set_addr_space(Some(AddrSpaceWrapper::new()?), token.downgrade());
    context
        .arch
        .setup_initial_call(&stack, func, userspace_allowed);

    context.kstack = Some(stack);
    context.userspace = userspace_allowed;

    let context_lock = Arc::new(ContextLock::new(context));
    let context_ref = ContextRef(Arc::clone(&context_lock));
    let run_ref = WeakContextRef(Arc::downgrade(&context_ref.0));
    idle_contexts(token.downgrade()).push_back(run_ref);
    contexts_mut(token.downgrade()).insert(context_ref);

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
