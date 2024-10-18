//! # Context management
//!
//! For resources on contexts, please consult [wikipedia](https://en.wikipedia.org/wiki/Context_switch) and  [osdev](https://wiki.osdev.org/Context_Switching)

use alloc::{borrow::Cow, collections::BTreeSet, sync::Arc, vec::Vec};

use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};
use spinning_top::RwSpinlock;
use syscall::ENOMEM;

use crate::{
    context::memory::AddrSpaceWrapper,
    cpu_set::LogicalCpuSet,
    interrupt::InterruptStack,
    paging::{RmmA, RmmArch, TableKind},
    percpu::PercpuBlock,
    sync::WaitMap,
    syscall::error::{Error, Result},
};

use self::{
    context::Kstack,
    process::{Process, ProcessId, ProcessInfo},
};
pub use self::{
    context::{BorrowedHtBuf, Context, Status, WaitpidKey},
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

/// Context switch function
pub mod switch;

/// File struct - defines a scheme and a file number
pub mod file;

/// Memory struct - contains a set of pages for a context
pub mod memory;

/// Process handling - TODO move to userspace
pub mod process;

/// Signal handling
pub mod signal;

/// Timeout handling
pub mod timeout;

pub use self::switch::switch_finish_hook;

/// Maximum context files
pub const CONTEXT_MAX_FILES: usize = 65_536;

pub use self::arch::empty_cr3;

static KMAIN_PROCESS: Once<Arc<RwLock<Process>>> = Once::new();

// Set of weak references to all contexts available for scheduling. The only strong references are
// the context file descriptors.
static CONTEXTS: RwLock<BTreeSet<ContextRef>> = RwLock::new(BTreeSet::new());

pub fn init() {
    let pid = ProcessId::new(0);
    let process = KMAIN_PROCESS.call_once(|| {
        Arc::new(RwLock::new(Process {
            info: ProcessInfo::default(),
            waitpid: Arc::new(WaitMap::new()),
            threads: Vec::new(),
            status: process::ProcessStatus::PossiblyRunnable,
        }))
    });

    let mut context =
        Context::new(pid, Arc::clone(process)).expect("failed to create kmain context");
    context.sched_affinity = LogicalCpuSet::empty();
    context.sched_affinity.atomic_set(crate::cpu_id());
    context.name = Cow::Borrowed("kmain");

    self::arch::EMPTY_CR3.call_once(|| unsafe { RmmA::table(TableKind::User) });

    context.status = Status::Runnable;
    context.running = true;
    context.cpu_id = Some(crate::cpu_id());

    let context_lock = Arc::new(RwSpinlock::new(context));

    CONTEXTS
        .write()
        .insert(ContextRef(Arc::clone(&context_lock)));

    unsafe {
        let percpu = PercpuBlock::current();
        percpu
            .switch_internals
            .set_current_context(Arc::clone(&context_lock));
        percpu.switch_internals.set_idle_context(context_lock);
    }
}

/// Get the global schemes list, const
pub fn contexts() -> RwLockReadGuard<'static, BTreeSet<ContextRef>> {
    CONTEXTS.read()
}

/// Get the global schemes list, mutable
pub fn contexts_mut() -> RwLockWriteGuard<'static, BTreeSet<ContextRef>> {
    CONTEXTS.write()
}

pub fn current() -> Arc<RwSpinlock<Context>> {
    PercpuBlock::current()
        .switch_internals
        .with_context(|context| Arc::clone(context))
}
pub fn is_current(context: &Arc<RwSpinlock<Context>>) -> bool {
    PercpuBlock::current()
        .switch_internals
        .with_context(|current| Arc::ptr_eq(context, current))
}

pub fn current_pid() -> Result<ProcessId> {
    Ok(current().read().pid)
}

pub struct ContextRef(pub Arc<RwSpinlock<Context>>);
impl ContextRef {
    pub fn upgrade(&self) -> Option<Arc<RwSpinlock<Context>>> {
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
    process: Arc<RwLock<Process>>,
    func: extern "C" fn(),
) -> Result<Arc<RwSpinlock<Context>>> {
    let stack = Kstack::new()?;

    let context_lock = Arc::try_new(RwSpinlock::new(Context::new(
        process.read().pid,
        Arc::clone(&process),
    )?))
    .map_err(|_| Error::new(ENOMEM))?;

    CONTEXTS
        .write()
        .insert(ContextRef(Arc::clone(&context_lock)));

    process.write().threads.push(Arc::downgrade(&context_lock));
    {
        let mut context = context_lock.write();
        let _ = context.set_addr_space(Some(AddrSpaceWrapper::new()?));

        let mut stack_top = stack.initial_top();

        const INT_REGS_SIZE: usize = core::mem::size_of::<crate::interrupt::InterruptStack>();

        if userspace_allowed {
            unsafe {
                // Zero-initialize InterruptStack registers.
                stack_top = stack_top.sub(INT_REGS_SIZE);
                stack_top.write_bytes(0_u8, INT_REGS_SIZE);
                (&mut *stack_top.cast::<InterruptStack>()).init();
            }
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            if userspace_allowed {
                stack_top = stack_top.sub(core::mem::size_of::<usize>());
                stack_top
                    .cast::<usize>()
                    .write(crate::interrupt::syscall::enter_usermode as usize);
            }

            stack_top = stack_top.sub(core::mem::size_of::<usize>());
            stack_top.cast::<usize>().write(func as usize);
        }

        #[cfg(target_arch = "aarch64")]
        {
            context
                .arch
                .set_lr(crate::interrupt::syscall::enter_usermode as usize);
            context.arch.set_x28(func as usize);
            context.arch.set_context_handle();
        }

        context.arch.set_stack(stack_top as usize);

        context.kstack = Some(stack);
        context.userspace = userspace_allowed;
    }
    Ok(context_lock)
}
