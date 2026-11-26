//! # Context management
//!
//! For resources on contexts, please consult [wikipedia](https://en.wikipedia.org/wiki/Context_switch) and  [osdev](https://wiki.osdev.org/Context_Switching)

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
};
use core::{
    cell::{Ref, RefMut},
    cmp::Reverse,
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
};
use syscall::MAX_CPU_COUNT;

use crate::{
    context::memory::AddrSpaceWrapper,
    cpu_set::{LogicalCpuId, LogicalCpuSet},
    cpu_stats::{CpuState, CpuStatsData},
    ipi::{ipi, IpiKind, IpiTarget},
    memory::{RmmA, RmmArch, TableKind},
    percpu::{self, get_percpu_block, PercpuBlock},
    sync::{CleanLockToken, LockToken, RwLock, RwLockReadGuard, RwLockWriteGuard, L1, L2, L3, L4},
    syscall::error::Result,
};

use self::context::Kstack;
pub use self::{
    context::{ArcContextLockWriteGuard, BorrowedHtBuf, Context, ContextLock, Status},
    switch::switch,
};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContextQueueKey {
    vd: u64,
    rem_slice: Reverse<u64>,
    ctxt_id: u32,
}

#[derive(Debug)]
pub struct ContextQueueValue {
    vtime: u64,
    weight: u64,
    context_ref: WeakContextRef,
}

#[derive(Debug)]
pub struct RunContextData {
    queue: BTreeMap<ContextQueueKey, ContextQueueValue>,
    timers: BTreeSet<(u128, WeakContextRef)>, // (wake, context)
    v: u64,
    total_weight: u64,
    min_vtime: u64,
}

impl RunContextData {
    pub const fn new() -> Self {
        Self {
            queue: BTreeMap::new(),
            timers: BTreeSet::new(),
            v: 0,
            total_weight: 0,
            min_vtime: 0,
        }
    }
    pub fn is_stealable(&self) -> bool {
        !self.queue.is_empty()
    }
    fn queue_insert(&mut self, k: ContextQueueKey, v: ContextQueueValue) {
        // it is forbidden to push kmain context
        /*
        if let Some(ctx) = v.context_ref.upgrade() {
            let mut t = unsafe { CleanLockToken::new() };
            if let Some(g) = ctx.try_read(t.token()) {
                if !g.userspace {
                    panic!(
                        "CPU {} was trying to push {:?} {id}",
                        crate::cpu_id().get(),
                        g.name.as_str(),
                    );
                }
            }
        }
        */
        self.queue.insert(k, v);
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

pub fn unblock_context(context_lock: &Arc<ContextLock>, token: &mut LockToken<'_, L3>) -> bool {
    if crate::context::is_current(context_lock) {
        return crate::context::current_mut().unblock_no_ipi();
    }

    let res = context_lock
        .write_unless_running(token, |guard| {
            if guard.unblock_no_ipi() {
                Some((true, guard.cpu_id))
            } else if guard.status.is_runnable() {
                Some((false, guard.cpu_id))
            } else {
                None
            }
        })
        .flatten();

    if let Some((unblocked, cpu_id)) = res {
        wakeup_context(context_lock, cpu_id, token);
        unblocked
    } else {
        false
    }
}

pub fn wakeup_context(
    context_lock: &Arc<ContextLock>,
    cpu_id: Option<LogicalCpuId>,
    token: &mut LockToken<'_, L3>,
) {
    let weak = WeakContextRef(Arc::downgrade(context_lock));
    let curr_cpu = crate::cpu_id();

    let target_cpu = cpu_id.unwrap_or(curr_cpu);

    if target_cpu != curr_cpu
        && let Some(percpu) = get_percpu_block(target_cpu)
    {
        // non-local wakeup
        percpu
            .switch_internals
            .ipi_context_wakeup_list
            .lock(token.token())
            .push(weak);
        ipi(IpiKind::Wakeup, IpiTarget::Other);
        return;
    }

    // local wakeup
    PercpuBlock::current()
        .switch_internals
        .local_wakeup_list
        .borrow_mut()
        .push(weak);
}

pub fn init(token: &mut CleanLockToken, kstack: Kstack) {
    let owner = None; // kmain not owned by any fd
    let mut context = Context::new(owner, kstack).expect("failed to create kmain context");
    let cpu_id = crate::cpu_id();
    (0..MAX_CPU_COUNT)
        .map(|e| LogicalCpuId::new(e))
        .for_each(|e| context.sched_affinity.atomic_clear(e));
    context.sched_affinity.atomic_set(cpu_id);

    context.name.clear();
    context.name.push_str("[kmain]");

    #[cfg(feature = "profiling")]
    {
        crate::profiling::DBG_ID_MAP
            .write(token.token())
            .insert(context.debug_id, context.name);
    }

    self::arch::EMPTY_CR3.call_once(|| RmmA::table(TableKind::User));

    context.status = Status::Runnable;
    context.cpu_id = Some(cpu_id);

    let context_lock = Arc::new(ContextLock::new(context));
    context_lock.set_cpu_id(cpu_id);

    let context_ref = ContextRef(Arc::clone(&context_lock));
    contexts_mut(token.token().downgrade()).insert(context_ref.clone());
    // Set this as current context and idle context, but don't treat it as regular context queue
    unsafe {
        let percpu = PercpuBlock::current();
        percpu
            .switch_internals
            .set_current_context(context_lock.write_arc());
        percpu
            .switch_internals
            .set_sched_context(Arc::clone(&context_lock));
        percpu.switch_internals.set_idle_context(context_lock);
    }
}
#[cfg_attr(feature = "drop_panic", track_caller)]
pub fn current() -> Ref<'static, ArcContextLockWriteGuard> {
    let percpu = PercpuBlock::current();
    #[cfg(feature = "drop_panic")]
    {
        let caller = core::panic::Location::caller();
        match percpu.switch_internals.current_context() {
            Ok(guard) => {
                percpu.switch_internals.last_borrow.set(Some(caller));
                guard
            }
            Err(_) => panic!(
                "current() borrow failed at {caller}; already borrowed at {:?}",
                percpu.switch_internals.last_borrow.get()
            ),
        }
    }
    #[cfg(not(feature = "drop_panic"))]
    {
        percpu
            .switch_internals
            .current_context()
            .expect("current() already borrowed")
    }
}

#[cfg_attr(feature = "drop_panic", track_caller)]
pub fn current_mut() -> RefMut<'static, ArcContextLockWriteGuard> {
    let percpu = PercpuBlock::current();
    #[cfg(feature = "drop_panic")]
    {
        let caller = core::panic::Location::caller();
        match percpu.switch_internals.current_context_mut() {
            Ok(guard) => {
                percpu.switch_internals.last_borrow.set(Some(caller));
                guard
            }
            Err(_) => panic!(
                "current_mut() borrow failed at {caller}; already borrowed at {:?}",
                percpu.switch_internals.last_borrow.get()
            ),
        }
    }
    #[cfg(not(feature = "drop_panic"))]
    {
        percpu
            .switch_internals
            .current_context_mut()
            .expect("current_mut() already borrowed")
    }
}

pub fn try_current() -> Option<Ref<'static, ArcContextLockWriteGuard>> {
    PercpuBlock::current()
        .switch_internals
        .current_context_raw()
}
pub fn is_current(context: &Arc<ContextLock>) -> bool {
    PercpuBlock::current()
        .switch_internals
        .current_context_raw()
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current.rwlock(), context))
}

pub enum ContextReadGuard<'a> {
    Current(Ref<'static, ArcContextLockWriteGuard>, LockToken<'a, L3>),
    Locked(RwLockReadGuard<'a, L4, Context>),
}

impl<'a> ContextReadGuard<'a> {
    pub fn token_split(&mut self) -> (&Context, LockToken<'_, L4>) {
        match self {
            ContextReadGuard::Current(cur, lock_token) => (cur, lock_token.downgrade()),
            ContextReadGuard::Locked(rw_lock_read_guard) => rw_lock_read_guard.token_split(),
        }
    }
}

impl Deref for ContextReadGuard<'_> {
    type Target = Context;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Current(g, _) => g,
            Self::Locked(g) => g,
        }
    }
}

#[cfg_attr(feature = "busy_panic", track_caller)]
pub fn read_context<'a>(
    context: &'a Arc<ContextLock>,
    mut token: LockToken<'a, L3>,
) -> ContextReadGuard<'a> {
    if crate::context::is_current(context) {
        ContextReadGuard::Current(crate::context::current(), token)
    } else {
        ContextReadGuard::Locked(context.read(token))
    }
}

#[cfg_attr(feature = "drop_panic", track_caller)]
pub fn try_read_context<'a>(
    context: &'a Arc<ContextLock>,
    token: LockToken<'a, L3>,
) -> Option<ContextReadGuard<'a>> {
    if crate::context::is_current(context) {
        Some(ContextReadGuard::Current(crate::context::current(), token))
    } else if context.cpu_id().is_some() {
        None
    } else {
        context.try_read(token).map(ContextReadGuard::Locked)
    }
}

pub enum ContextWriteGuard<'a> {
    Current(RefMut<'static, ArcContextLockWriteGuard>, LockToken<'a, L3>),
    Locked(RwLockWriteGuard<'a, L4, Context>),
}

impl<'a> ContextWriteGuard<'a> {
    #[inline]
    pub fn token_split(&mut self) -> (&mut Context, LockToken<'_, L4>) {
        match self {
            ContextWriteGuard::Current(cur, lock_token) => (cur, lock_token.downgrade()),
            ContextWriteGuard::Locked(rw_lock_write_guard) => rw_lock_write_guard.token_split(),
        }
    }
}

impl Deref for ContextWriteGuard<'_> {
    type Target = Context;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Current(g, _) => g,
            Self::Locked(g) => g,
        }
    }
}

impl DerefMut for ContextWriteGuard<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Current(g, _) => g,
            Self::Locked(g) => g,
        }
    }
}

#[cfg_attr(feature = "busy_panic", track_caller)]
pub fn write_context<'a>(
    context: &'a Arc<ContextLock>,
    token: LockToken<'a, L3>,
) -> ContextWriteGuard<'a> {
    if crate::context::is_current(context) {
        ContextWriteGuard::Current(crate::context::current_mut(), token)
    } else {
        ContextWriteGuard::Locked(context.write(token))
    }
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
impl core::fmt::Debug for WeakContextRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:p}", Weak::as_ptr(&self.0))
    }
}

/// Spawn a context from a function.
pub fn spawn(
    userspace_allowed: bool,
    owner_proc_id: Option<NonZeroUsize>,
    func: extern "C" fn(),
    token: &mut CleanLockToken,
) -> Result<Arc<ContextLock>> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let cpu_id = percpu::PercpuBlock::current()
        .misc_arch_info
        .apic_id_opt
        .get()
        .map(|e| e.get());

    #[cfg(all(not(target_arch = "x86"), not(target_arch = "x86_64")))]
    let cpu_id = None;

    let stack = Kstack::new(cpu_id)?;

    let mut context = Context::new(owner_proc_id, stack)?;

    let _ = context.set_addr_space(Some(AddrSpaceWrapper::new()?), token.downgrade());
    context
        .arch
        .setup_initial_call(&context.kstack, func, userspace_allowed);

    context.userspace = userspace_allowed;

    let context_lock = Arc::new(ContextLock::new(context));
    let context_ref = ContextRef(Arc::clone(&context_lock));
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
pub struct PreemptGuardL1 {}

impl PreemptGuardL1 {
    pub fn new() -> PreemptGuardL1 {
        current_mut().preempt_locks += 1;
        PreemptGuardL1 {}
    }
}

impl Drop for PreemptGuardL1 {
    fn drop(&mut self) {
        current_mut().preempt_locks -= 1;
    }
}

pub fn get_contexts_stats(token: &mut CleanLockToken) -> [usize; 6] {
    let alive = contexts(token.downgrade()).len();

    let mut running = 0;
    let mut switches = 0;
    let mut syscall_switches = 0;
    let mut idling_cpu = 0;

    for percpu in crate::percpu::all_percpu_blocks() {
        let queue = percpu.switch_internals.run_queue.lock().queue.len();
        let is_idle = percpu.stats.get_state() as u8 == CpuState::Idle as u8;

        running += queue + if !is_idle { 1 } else { 0 };

        let data = CpuStatsData::from(&percpu.stats);
        switches += data.context_switches as usize;
        syscall_switches += data.syscall_switches as usize;

        if is_idle {
            idling_cpu += 1;
        }
    }

    let blocked = alive.saturating_sub(running);

    [
        alive,
        running,
        blocked,
        switches,
        syscall_switches,
        idling_cpu,
    ]
}
