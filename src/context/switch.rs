///! This module provides a context-switching mechanism that utilizes a simple round-robin scheduler.
///! The scheduler iterates over available contexts, selecting the next context to run, while
///! handling process states and synchronization.
use core::{
    cell::{Cell, RefCell},
    mem,
    ops::Bound,
    sync::atomic::Ordering,
};

use alloc::sync::Arc;
use spinning_top::{guard::ArcRwSpinlockWriteGuard, RwSpinlock};
use syscall::PtraceFlags;

use crate::{
    context::{arch, contexts, Context},
    cpu_set::LogicalCpuId,
    interrupt,
    percpu::PercpuBlock,
    ptrace, time,
};

use super::ContextRef;

enum UpdateResult {
    CanSwitch,
    Skip,
}

/// Determines if a given context is eligible to be scheduled on a given CPU (in
/// principle, the current CPU).
///
/// # Safety
/// This function is unsafe because it modifies the `context`'s state directly without synchronization.
///
/// # Parameters
/// - `context`: The context (process/thread) to be checked.
/// - `cpu_id`: The logical ID of the CPU on which the context is being scheduled.
///
/// # Returns
/// - `UpdateResult::CanSwitch`: If the context can be switched to.
/// - `UpdateResult::Skip`: If the context should be skipped (e.g., it's running on another CPU).
unsafe fn update_runnable(context: &mut Context, cpu_id: LogicalCpuId) -> UpdateResult {
    // Ignore contexts that are already running.
    if context.running {
        return UpdateResult::Skip;
    }

    // Ignore contexts assigned to other CPUs.
    if !context.sched_affinity.contains(cpu_id) {
        return UpdateResult::Skip;
    }

    //TODO: HACK TO WORKAROUND HANGS BY PINNING TO ONE CPU
    if !context.cpu_id.map_or(true, |x| x == cpu_id) {
        return UpdateResult::Skip;
    }

    // If context is soft-blocked and has a wake-up time, check if it should wake up.
    if context.status.is_soft_blocked() {
        if let Some(wake) = context.wake {
            let current = time::monotonic();
            if current >= wake {
                context.wake = None;
                context.unblock_no_ipi();
            }
        }
    }

    // If the context is runnable, indicate it can be switched to.
    if context.status.is_runnable() {
        UpdateResult::CanSwitch
    } else {
        UpdateResult::Skip
    }
}

struct SwitchResultInner {
    _prev_guard: ArcRwSpinlockWriteGuard<Context>,
    _next_guard: ArcRwSpinlockWriteGuard<Context>,
}

/// Tick function to update PIT ticks and trigger a context switch if necessary.
///
/// Called periodically, this function increments a per-CPU tick counter and performs a context
/// switch if the counter reaches a set threshold (e.g., every 3 ticks).
///
/// The function also calls the signal handler after switching contexts.
pub fn tick() {
    let ticks_cell = &PercpuBlock::current().switch_internals.pit_ticks;

    let new_ticks = ticks_cell.get() + 1;
    ticks_cell.set(new_ticks);

    // Trigger a context switch after every 3 ticks (approx. 6.75 ms).
    if new_ticks >= 3 {
        switch();
        crate::context::signal::signal_handler();
    }
}

/// Finishes the context switch by clearing any temporary data and resetting the lock.
///
/// This function is called after a context switch is completed to perform cleanup, including
/// clearing the switch result data and releasing the context switch lock.
///
/// # Safety
/// This function involves unsafe operations such as resetting state and releasing locks.
pub unsafe extern "C" fn switch_finish_hook() {
    if let Some(switch_result) = PercpuBlock::current().switch_internals.switch_result.take() {
        drop(switch_result);
    } else {
        // TODO: unreachable_unchecked()?
        crate::arch::stop::emergency_reset();
    }
    arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);
    crate::percpu::switch_arch_hook();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchResult {
    Switched,
    AllContextsIdle,
}

/// Selects and switches to the next context using a round-robin scheduler.
///
/// This function performs the context switch, checking each context in a loop for eligibility
/// until it finds a context ready to run. If no other context is runnable, it returns to the
/// idle context.
///
/// # Warning
/// This is not memory-unsafe to call. But do NOT call this while holding locks!
///
/// # Returns
/// - `SwitchResult::Switched`: Indicates a successful switch to a new context.
/// - `SwitchResult::AllContextsIdle`: Indicates all contexts are idle, and the CPU will switch
///   to an idle context.
pub fn switch() -> SwitchResult {
    let percpu = PercpuBlock::current();

    //set PIT Interrupt counter to 0, giving each process same amount of PIT ticks
    percpu.switch_internals.pit_ticks.set(0);

    // Acquire the global lock to ensure exclusive access during context switch and avoid
    // issues that would be caused by the unsafe operations below
    // TODO: Better memory orderings?
    while arch::CONTEXT_SWITCH_LOCK
        .compare_exchange_weak(false, true, Ordering::SeqCst, Ordering::Relaxed)
        .is_err()
    {
        interrupt::pause();
        percpu.maybe_handle_tlb_shootdown();
    }

    let cpu_id = crate::cpu_id();

    let mut switch_context_opt = None;
    {
        let contexts = contexts();

        // Lock the previous context.
        let prev_context_lock = crate::context::current();
        let prev_context_guard = prev_context_lock.write_arc();

        let idle_context = percpu.switch_internals.idle_context();

        // Stateful flag used to skip the idle process the first time it shows up.
        // After that, this flag is set to `false` so the idle process can be
        // picked up.
        let mut skip_idle = true;

        // Attempt to locate the next context to switch to.
        for next_context_lock in contexts
            // Include all contexts with IDs greater than the current...
            .range((
                Bound::Excluded(ContextRef(Arc::clone(&prev_context_lock))),
                Bound::Unbounded,
            ))
            // ... and all contexts with IDs less than the current...
            .chain(contexts.range((
                Bound::Unbounded,
                Bound::Excluded(ContextRef(Arc::clone(&prev_context_lock))),
            )))
            .filter_map(ContextRef::upgrade)
            // ... and the idle context...
            .chain(Some(Arc::clone(&idle_context)))
        // ... but not the current context (note the `Bound::Excluded`),
        // which is already locked.
        {
            if Arc::ptr_eq(&next_context_lock, &idle_context) && skip_idle {
                // Skip idle process the first time it shows up, but allow it
                // to be picked up again the next time.
                skip_idle = false;
                continue;
            }

            // Lock next context
            let mut next_context_guard = next_context_lock.write_arc();

            // Check if the context is runnable and can be switched to.
            if let UpdateResult::CanSwitch =
                unsafe { update_runnable(&mut *next_context_guard, cpu_id) }
            {
                // Store locks for previous and next context and break out from loop
                // for the switch
                switch_context_opt = Some((prev_context_guard, next_context_guard));
                break;
            }
        }
    };

    // Switch process states, TSS stack pointer, and store new context ID
    if let Some((mut prev_context_guard, mut next_context_guard)) = switch_context_opt {
        // Update context states and prepare for the switch.
        let prev_context = &mut *prev_context_guard;
        let next_context = &mut *next_context_guard;

        // Set the previous context as "not running"
        prev_context.running = false;

        // Set the next context as "running"
        next_context.running = true;
        // Set the CPU ID for the next context
        next_context.cpu_id = Some(cpu_id);

        let percpu = PercpuBlock::current();
        unsafe {
            percpu.switch_internals.set_current_context(Arc::clone(
                ArcRwSpinlockWriteGuard::rwlock(&next_context_guard),
            ));
        }

        // FIXME set the switch result in arch::switch_to instead
        let prev_context =
            unsafe { mem::transmute::<&'_ mut Context, &'_ mut Context>(&mut *prev_context_guard) };
        let next_context =
            unsafe { mem::transmute::<&'_ mut Context, &'_ mut Context>(&mut *next_context_guard) };

        percpu
            .switch_internals
            .switch_result
            .set(Some(SwitchResultInner {
                _prev_guard: prev_context_guard,
                _next_guard: next_context_guard,
            }));

        let (ptrace_session, ptrace_flags) = if let Some((session, bp)) = ptrace::sessions()
            .get(&next_context.pid)
            .map(|s| (Arc::downgrade(s), s.data.lock().breakpoint))
        {
            (Some(session), bp.map_or(PtraceFlags::empty(), |f| f.flags))
        } else {
            (None, PtraceFlags::empty())
        };

        *percpu.ptrace_session.borrow_mut() = ptrace_session;
        percpu.ptrace_flags.set(ptrace_flags);
        prev_context.inside_syscall = percpu.inside_syscall.replace(next_context.inside_syscall);

        #[cfg(feature = "syscall_debug")]
        {
            prev_context.syscall_debug_info = percpu
                .syscall_debug_info
                .replace(next_context.syscall_debug_info);
            prev_context.syscall_debug_info.on_switch_from();
            next_context.syscall_debug_info.on_switch_to();
        }

        percpu
            .switch_internals
            .being_sigkilled
            .set(next_context.being_sigkilled);

        unsafe {
            arch::switch_to(prev_context, next_context);
        }

        // NOTE: After switch_to is called, the return address can even be different from the
        // current return address, meaning that we cannot use local variables here, and that we
        // need to use the `switch_finish_hook` to be able to release the locks. Newly created
        // contexts will return directly to the function pointer passed to context::spawn, and not
        // reach this code until the next context switch back.

        SwitchResult::Switched
    } else {
        // No target was found, unset global lock and return
        arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);

        SwitchResult::AllContextsIdle
    }
}

/// Holds per-CPU state necessary for context switching.
///
/// This struct contains information such as the idle context, current context, and PIT tick counts,
/// as well as fields required for managing ptrace sessions and signals.
#[derive(Default)]
pub struct ContextSwitchPercpu {
    switch_result: Cell<Option<SwitchResultInner>>,
    pit_ticks: Cell<usize>,

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
