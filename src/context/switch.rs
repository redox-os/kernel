use core::{cell::Cell, mem, ops::Bound, sync::atomic::Ordering};

use alloc::sync::Arc;
use spinning_top::guard::ArcRwSpinlockWriteGuard;
use syscall::PtraceFlags;

use crate::{
    context::{arch, contexts, Context}, cpu_set::LogicalCpuId, interrupt, percpu::PercpuBlock, ptrace, time
};

use super::{ContextId, Status};

enum UpdateResult {
    CanSwitch { signal: bool },
    Skip,
}

unsafe fn update_runnable(context: &mut Context, cpu_id: LogicalCpuId) -> UpdateResult {
    // Ignore already running contexts
    if context.running {
        return UpdateResult::Skip;
    }

    // Ignore contexts stopped by ptrace
    // TODO: ContextStatus::HardBlocked?
    if context.ptrace_stop {
        return UpdateResult::Skip;
    }

    // Ignore contexts assigned to other CPUs
    if !context.sched_affinity.contains(cpu_id) {
        return UpdateResult::Skip;
    }

    //TODO: HACK TO WORKAROUND HANGS BY PINNING TO ONE CPU
    if !context.cpu_id.map_or(true, |x| x == cpu_id) {
        return UpdateResult::Skip;
    }

    let signal = context.sig.deliverable() != 0;

    // Unblock when there are pending nonmasked signals.
    if matches!(context.status, Status::Blocked) && signal {
        context.unblock_no_ipi();
    }

    // Wake from sleep
    if context.status.is_soft_blocked() && context.wake.is_some() {
        let wake = context.wake.expect("context::switch: wake not set");

        let current = time::monotonic();
        if current >= wake {
            context.wake = None;
            context.unblock_no_ipi();
        }
    }

    // Switch to context if it needs to run
    if context.status.is_runnable() {
        UpdateResult::CanSwitch { signal }
    } else {
        UpdateResult::Skip
    }
}

struct SwitchResultInner {
    _prev_guard: ArcRwSpinlockWriteGuard<Context>,
    _next_guard: ArcRwSpinlockWriteGuard<Context>,
}

pub fn tick() {
    let ticks_cell = &PercpuBlock::current().switch_internals.pit_ticks;

    let new_ticks = ticks_cell.get() + 1;
    ticks_cell.set(new_ticks);

    // Switch after 3 ticks (about 6.75 ms)
    if new_ticks >= 3 {
        match switch() {
            SwitchResult::Switched { signal: true } => {
                crate::context::signal::signal_handler();
            },
            _ => (),
        }
    }
}

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
    Switched { signal: bool },
    AllContextsIdle,
}

/// Switch to the next context, picked by the scheduler.
///
/// This is not memory-unsafe to call, but do NOT call this while holding locks!
pub fn switch() -> SwitchResult {
    let percpu = PercpuBlock::current();

    //set PIT Interrupt counter to 0, giving each process same amount of PIT ticks
    percpu.switch_internals.pit_ticks.set(0);

    // Set the global lock to avoid the unsafe operations below from causing issues
    // TODO: Better memory orderings?
    while arch::CONTEXT_SWITCH_LOCK
        .compare_exchange_weak(false, true, Ordering::SeqCst, Ordering::Relaxed)
        .is_err()
    {
        interrupt::pause();
        percpu.maybe_handle_tlb_shootdown();
    }

    let cpu_id = crate::cpu_id();
    let switch_time = crate::time::monotonic();

    let mut switch_context_opt = None;
    {
        let contexts = contexts();

        // Lock previous context
        let prev_context_lock = contexts
            .current()
            .expect("context::switch: not inside of context");
        let prev_context_guard = prev_context_lock.write_arc();

        let idle_id = percpu.switch_internals.idle_id();
        let mut skip_idle = true;

        // Locate next context
        for (pid, next_context_lock) in contexts
            // Include all contexts with IDs greater than the current...
            .range((Bound::Excluded(prev_context_guard.id), Bound::Unbounded))
            .chain(
                contexts
                    // ... and all contexts with IDs less than the current...
                    .range((Bound::Unbounded, Bound::Excluded(prev_context_guard.id))),
            )
            .chain(
                contexts
                    // ... and finally the idle ID
                    .range((Bound::Included(idle_id), Bound::Included(idle_id))),
            )
        // ... but not the current context, which is already locked
        {
            if pid == &idle_id && skip_idle {
                // Skip idle process the first time it shows up
                skip_idle = false;
                continue;
            }

            // Lock next context
            let mut next_context_guard = next_context_lock.write_arc();

            // Update state of next context and check if runnable
            if let UpdateResult::CanSwitch { signal } = unsafe { update_runnable(&mut *next_context_guard, cpu_id) } {
                // Store locks for previous and next context
                switch_context_opt = Some((prev_context_guard, next_context_guard));
                percpu.switch_internals.switch_signal.set(signal);
                break;
            } else {
                continue;
            }
        }
    };

    // Switch process states, TSS stack pointer, and store new context ID
    if let Some((mut prev_context_guard, mut next_context_guard)) = switch_context_opt {
        // TODO: Update timestamps in switch_to

        // Set old context as not running and update CPU time
        let prev_context = &mut *prev_context_guard;
        prev_context.running = false;
        prev_context.cpu_time += switch_time.saturating_sub(prev_context.switch_time);

        // Set new context as running and set switch time
        let next_context = &mut *next_context_guard;
        next_context.running = true;
        next_context.cpu_id = Some(cpu_id);
        next_context.switch_time = switch_time;

        let percpu = PercpuBlock::current();
        percpu.switch_internals.context_id.set(next_context.id);

        // FIXME set th switch result in arch::switch_to instead
        let prev_context = unsafe {
            mem::transmute::<&'_ mut Context, &'_ mut Context>(&mut *prev_context_guard)
        };
        let next_context = unsafe {
            mem::transmute::<&'_ mut Context, &'_ mut Context>(&mut *next_context_guard)
        };

        percpu
            .switch_internals
            .switch_result
            .set(Some(SwitchResultInner {
                _prev_guard: prev_context_guard,
                _next_guard: next_context_guard,
            }));

        let (ptrace_session, ptrace_flags) = if let Some((session, bp)) = ptrace::sessions().get(&next_context.id).map(|s| (Arc::downgrade(s), s.data.lock().breakpoint)) {
            (Some(session), bp.map_or(PtraceFlags::empty(), |f| f.flags))
        } else { (None, PtraceFlags::empty()) };

        *percpu.ptrace_session.borrow_mut() = ptrace_session;
        percpu.ptrace_flags.set(ptrace_flags);
        prev_context.inside_syscall = percpu.inside_syscall.replace(next_context.inside_syscall);

        #[cfg(feature = "syscall_debug")]
        {
            prev_context.syscall_debug_info = percpu.syscall_debug_info.replace(next_context.syscall_debug_info);
            prev_context.syscall_debug_info.on_switch_from();
            next_context.syscall_debug_info.on_switch_to();
        }

        unsafe {
            arch::switch_to(prev_context, next_context);
        }

        // NOTE: After switch_to is called, the return address can even be different from the
        // current return address, meaning that we cannot use local variables here, and that we
        // need to use the `switch_finish_hook` to be able to release the locks. Newly created
        // contexts will return directly to the function pointer passed to context::spawn, and not
        // reach this code until the next context switch back.

        let new_percpu = PercpuBlock::current();
        // For the same reason, we obviously can't reuse the percpu block

        SwitchResult::Switched { signal: new_percpu.switch_internals.switch_signal.get() }
    } else {
        // No target was found, unset global lock and return
        arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);

        SwitchResult::AllContextsIdle
    }
}

#[derive(Default)]
pub struct ContextSwitchPercpu {
    switch_result: Cell<Option<SwitchResultInner>>,
    pit_ticks: Cell<usize>,

    /// Unique ID of the currently running context.
    context_id: Cell<ContextId>,

    // The ID of the idle process
    idle_id: Cell<ContextId>,
    switch_signal: Cell<bool>,
}
impl ContextSwitchPercpu {
    pub fn context_id(&self) -> ContextId {
        self.context_id.get()
    }
    pub unsafe fn set_context_id(&self, new: ContextId) {
        self.context_id.set(new)
    }
    pub fn idle_id(&self) -> ContextId {
        self.idle_id.get()
    }
    pub unsafe fn set_idle_id(&self, new: ContextId) {
        self.idle_id.set(new)
    }
}
