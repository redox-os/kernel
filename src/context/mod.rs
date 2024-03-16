//! # Context management
//!
//! For resources on contexts, please consult [wikipedia](https://en.wikipedia.org/wiki/Context_switch) and  [osdev](https://wiki.osdev.org/Context_Switching)

use alloc::{borrow::Cow, sync::Arc};

use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use spinning_top::RwSpinlock;

use crate::{
    cpu_set::LogicalCpuSet,
    paging::{RmmA, RmmArch, TableKind},
    percpu::PercpuBlock,
    syscall::error::{Error, Result, ESRCH},
};

pub use self::{
    context::{BorrowedHtBuf, Context, ContextId, Status, WaitpidKey},
    list::ContextList,
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

/// Context struct
pub mod context;

/// Context list
mod list;

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

/// Limit on number of contexts
pub const CONTEXT_MAX_CONTEXTS: usize = (isize::max_value() as usize) - 1;

/// Maximum context files
pub const CONTEXT_MAX_FILES: usize = 65_536;

/// Contexts list
static CONTEXTS: RwLock<ContextList> = RwLock::new(ContextList::new());

pub use self::arch::empty_cr3;

pub fn init() {
    let mut contexts = contexts_mut();
    let id = ContextId::from(crate::cpu_id().get() as usize + 1);
    let context_lock = contexts
        .insert_context_raw(id)
        .expect("could not initialize first context");
    let mut context = context_lock.write();
    context.sched_affinity = LogicalCpuSet::empty();
    context.sched_affinity.atomic_set(crate::cpu_id());
    context.name = Cow::Borrowed("kmain");
    context.sig.procmask = 0;

    self::arch::EMPTY_CR3.call_once(|| unsafe { RmmA::table(TableKind::User) });

    context.status = Status::Runnable;
    context.running = true;
    context.cpu_id = Some(crate::cpu_id());

    unsafe {
        let percpu = PercpuBlock::current();
        percpu.switch_internals.set_context_id(context.id);
        percpu.switch_internals.set_idle_id(context.id);
    }
}

/// Get the global schemes list, const
pub fn contexts() -> RwLockReadGuard<'static, ContextList> {
    CONTEXTS.read()
}

/// Get the global schemes list, mutable
pub fn contexts_mut() -> RwLockWriteGuard<'static, ContextList> {
    CONTEXTS.write()
}

pub fn context_id() -> ContextId {
    PercpuBlock::current().switch_internals.context_id()
}

pub fn current() -> Result<Arc<RwSpinlock<Context>>> {
    contexts()
        .current()
        .ok_or(Error::new(ESRCH))
        .map(Arc::clone)
}
