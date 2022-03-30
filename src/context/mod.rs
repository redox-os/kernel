//! # Context management
//!
//! For resources on contexts, please consult [wikipedia](https://en.wikipedia.org/wiki/Context_switch) and  [osdev](https://wiki.osdev.org/Context_Switching)
use alloc::boxed::Box;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::Ordering;
use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub use self::context::{Context, ContextId, ContextSnapshot, Status, WaitpidKey};
pub use self::list::ContextList;
pub use self::switch::switch;

#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64.rs"]
mod arch;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
mod arch;

/// Context struct
mod context;

/// Context list
mod list;

/// Context switch function
mod switch;

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

#[thread_local]
static CONTEXT_ID: context::AtomicContextId = context::AtomicContextId::default();

pub fn init() {
    let mut contexts = contexts_mut();
    let context_lock = contexts.new_context().expect("could not initialize first context");
    let mut context = context_lock.write();
    let mut fx = unsafe { Box::from_raw(crate::ALLOCATOR.alloc(Layout::from_size_align_unchecked(1024, 16)) as *mut [u8; 1024]) };
    for b in fx.iter_mut() {
        *b = 0;
    }

    context.arch.set_fx(fx.as_ptr() as usize);
    context.kfx = Some(fx);
    context.status = Status::Runnable;
    context.running = true;
    context.cpu_id = Some(crate::cpu_id());
    CONTEXT_ID.store(context.id, Ordering::SeqCst);
}

/// Initialize contexts, called if needed
fn init_contexts() -> RwLock<ContextList> {
    RwLock::new(ContextList::new())
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
    // Thread local variables can and should only be modified using Relaxed. This is to prevent a
    // hardware thread from racing with itself, for example if there is an interrupt. Orderings
    // stronger than Relaxed are only necessary for inter-processor synchronization.
    let id = CONTEXT_ID.load(Ordering::Relaxed);
    // Prevent the compiler from reordering subsequent loads and stores to before this load.
    core::sync::atomic::compiler_fence(Ordering::Acquire);
    id
}
