//! This module provides a context-switching mechanism that utilizes a simple round-robin scheduler.
//! The scheduler iterates over available contexts, selecting the next context to run, while
//! handling process states and synchronization.

use crate::{
    context::{self, arch, contexts, run_contexts, ArcContextLockWriteGuard, Context, ContextLock},
    cpu_set::LogicalCpuId,
    cpu_stats::{self, CpuState},
    percpu::PercpuBlock,
    sync::{ArcRwLockWriteGuard, CleanLockToken, L4},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    hint, mem,
    sync::atomic::Ordering,
};
use lfll::List;
use syscall::PtraceFlags;

use super::ContextRef;

enum UpdateResult {
    CanSwitch,
    Skip,
}

// A simple geometric series where value[i] ~= value[i - 1] * 1.25
const SCHED_PRIO_TO_WEIGHT: [usize; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

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
unsafe fn update_runnable(
    context: &mut Context,
    cpu_id: LogicalCpuId,
    switch_time: u128,
) -> UpdateResult {
    // Ignore contexts that are already running.
    if context.running {
        return UpdateResult::Skip;
    }

    // Ignore contexts assigned to other CPUs.
    if !context.sched_affinity.contains(cpu_id) {
        return UpdateResult::Skip;
    }

    // If context is soft-blocked and has a wake-up time, check if it should wake up.
    if context.status.is_soft_blocked()
        && let Some(wake) = context.wake
        && switch_time >= wake
    {
        context.wake = None;
        context.unblock_no_ipi();
    }

    // If the context is runnable, indicate it can be switched to.
    if context.status.is_runnable() {
        UpdateResult::CanSwitch
    } else {
        UpdateResult::Skip
    }
}

struct SwitchResultInner {
    _prev_guard: ArcContextLockWriteGuard,
    _next_guard: ArcContextLockWriteGuard,
}

/// Tick function to update PIT ticks and trigger a context switch if necessary.
///
/// Called periodically, this function increments a per-CPU tick counter and performs a context
/// switch if the counter reaches a set threshold (e.g., every 3 ticks).
///
/// The function also calls the signal handler after switching contexts.
pub fn tick(token: &mut CleanLockToken) {
    let ticks_cell = &PercpuBlock::current().switch_internals.pit_ticks;

    let new_ticks = ticks_cell.get() + 1;
    ticks_cell.set(new_ticks);

    // Trigger a context switch after every 3 ticks (approx. 6.75 ms).
    if new_ticks >= 3 {
        switch(token);
        crate::context::signal::signal_handler(token);
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
    unsafe {
        match PercpuBlock::current().switch_internals.switch_result.take() {
            Some(switch_result) => {
                drop(switch_result);
            }
            _ => {
                // TODO: unreachable_unchecked()?
                crate::arch::stop::emergency_reset();
            }
        }
        arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);
        crate::percpu::switch_arch_hook();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchResult {
    Switched,
    AllContextsIdle,
}

/// This function performs the context switch, using select_next_context to
/// actually select the next context to switch to.
///
/// # Warning
/// This is not memory-unsafe to call. But do NOT call this while holding locks!
///
/// # Returns
/// - `SwitchResult::Switched`: Indicates a successful switch to a new context.
/// - `SwitchResult::AllContextsIdle`: Indicates all contexts are idle, and the CPU will switch
///   to an idle context.
pub fn switch(token: &mut CleanLockToken) -> SwitchResult {
    let switch_time = crate::time::monotonic(token);

    let percpu = PercpuBlock::current();
    cpu_stats::add_context_switch();

    //set PIT Interrupt counter to 0, giving each process same amount of PIT ticks
    percpu.switch_internals.pit_ticks.set(0);

    // Acquire the global lock to ensure exclusive access during context switch and avoid
    // issues that would be caused by the unsafe operations below
    // TODO: Better memory orderings?
    while arch::CONTEXT_SWITCH_LOCK
        .compare_exchange_weak(false, true, Ordering::SeqCst, Ordering::Relaxed)
        .is_err()
    {
        hint::spin_loop();
        percpu.maybe_handle_tlb_shootdown();
    }

    // Lock the previous context.
    let prev_context_lock = crate::context::current();
    // We are careful not to lock this context twice
    let mut prev_context_guard = unsafe { prev_context_lock.write_arc() };

    if !prev_context_guard.is_preemptable() {
        // Unset global lock
        arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);

        // Pretend to have finished switching, so CPU is not idled
        return SwitchResult::Switched;
    }

    // Alarm (previously in update_runnable)
    // TODO: Optimise this somehow. Perhaps using a separate timer queue?
    let mut wakeups = Vec::new();
    {
        let current_context = context::current();

        let mut context = contexts();
        for context_ref in context.iter().filter_map(|(_, r)| r.upgrade()) {
            if Arc::ptr_eq(&context_ref, &current_context) {
                continue;
            }
            let guard = context_ref.read(token.token());
            if guard.status.is_soft_blocked() {
                if let Some(wake) = guard.wake {
                    if switch_time >= wake {
                        wakeups.push(Arc::clone(&context_ref));
                        continue;
                    }
                }
            }

            if guard.status.is_runnable() && !guard.enqueued && !guard.running {
                wakeups.push(Arc::clone(&context_ref));
            }
        }
    }
    for context_lock in wakeups {
        context::wakeup_context(&context_lock, token.token());
    }

    let cpu_id = crate::cpu_id();

    // Update per-cpu times
    let percpu_nanos = switch_time.saturating_sub(percpu.switch_internals.switch_time.get()) as u64;
    let percpu_ms = percpu_nanos / 1_000_000;
    let was_idle = percpu.stats.add_time(percpu_ms) == CpuState::Idle as u8;
    percpu.switch_internals.switch_time.set(switch_time);

    let switch_context_opt = match select_next_context(
        token,
        percpu,
        cpu_id,
        switch_time,
        was_idle,
        &mut prev_context_guard,
    ) {
        Ok(opt) => opt,
        Err(early_ret) => return early_ret,
    };

    // Switch process states, TSS stack pointer, and store new context ID
    match switch_context_opt {
        Some(mut next_context_guard) => {
            // Update context states and prepare for the switch.
            let prev_context = &mut *prev_context_guard;
            let next_context = &mut *next_context_guard;

            // Set the previous context as "not running"
            prev_context.running = false;

            // Set the next context as "running"
            next_context.running = true;
            // Set the CPU ID for the next context
            next_context.cpu_id = Some(cpu_id);

            // Update times
            if !was_idle {
                prev_context.cpu_time += switch_time.saturating_sub(prev_context.switch_time);
            }
            next_context.switch_time = switch_time;
            if next_context.userspace {
                percpu.stats.set_state(cpu_stats::CpuState::User);
            } else {
                percpu.stats.set_state(cpu_stats::CpuState::Kernel);
            }
            unsafe {
                percpu.switch_internals.set_current_context(Arc::clone(
                    ArcContextLockWriteGuard::rwlock(&next_context_guard),
                ));
            }

            // FIXME set the switch result in arch::switch_to instead
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

            /*let (ptrace_session, ptrace_flags) = if let Some((session, bp)) = ptrace::sessions()
                .get(&next_context.pid)
                .map(|s| (Arc::downgrade(s), s.data.lock().breakpoint))
            {
                (Some(session), bp.map_or(PtraceFlags::empty(), |f| f.flags))
            } else {
                (None, PtraceFlags::empty())
            };*/
            let ptrace_flags = PtraceFlags::empty();

            //*percpu.ptrace_session.borrow_mut() = ptrace_session;
            percpu.ptrace_flags.set(ptrace_flags);
            prev_context.inside_syscall =
                percpu.inside_syscall.replace(next_context.inside_syscall);

            #[cfg(feature = "syscall_debug")]
            {
                prev_context.syscall_debug_info = percpu
                    .syscall_debug_info
                    .replace(next_context.syscall_debug_info);
                prev_context.syscall_debug_info.on_switch_from(token);
                next_context.syscall_debug_info.on_switch_to(token);
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
        }
        _ => {
            // No target was found, unset global lock and return
            arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);

            percpu.stats.set_state(cpu_stats::CpuState::Idle);

            SwitchResult::AllContextsIdle
        }
    }
}

/// This is the scheduler function which currently utilises Deficit Weighted Round Robin Scheduler
fn select_next_context(
    token: &mut CleanLockToken,
    percpu: &PercpuBlock,
    cpu_id: LogicalCpuId,
    switch_time: u128,
    was_idle: bool,
    prev_context_guard: &mut ArcRwLockWriteGuard<L4, Context>,
) -> Result<Option<ArcContextLockWriteGuard>, SwitchResult> {
    let mut contexts_data = run_contexts(token.token());
    let contexts_list = &mut contexts_data.set;
    let mut balance = percpu.balance.get();
    let mut i = percpu.last_queue.get() % 40;

    // Lock the previous context.
    let prev_context_lock = crate::context::current();

    let mut empty_queues = 0;
    let mut total_iters = 0;
    let mut next_context_guard_opt = None;

    let total_contexts: usize = contexts_list.iter().map(|q| q.len()).sum();
    let mut skipped_contexts = 0;

    'priority: loop {
        i = (i + 1) % 40;
        total_iters += 1;

        // The least prioritised queue takes <5000 iters to build up
        // balance = sched_prio_to_weight[20], if we have already spent
        // that many iters and not found any context, it is better to just
        // skip for now
        if total_iters >= 5000 {
            break 'priority;
        }

        if skipped_contexts > total_contexts && total_contexts > 0 {
            break 'priority;
        }

        let contexts = contexts_list
            .get_mut(i)
            .expect("i should be between [0, 39]!");

        if contexts.is_empty() {
            empty_queues += 1;
            if empty_queues >= 40 {
                // If all queues are empty, just break out
                break 'priority;
            }
            continue;
        } else {
            empty_queues = 0;
        }

        if balance[i] < SCHED_PRIO_TO_WEIGHT[20] {
            // This queue does not have enough balance to run,
            // increment the balance!
            balance[i] += SCHED_PRIO_TO_WEIGHT[i];
            continue;
        }

        let len = contexts.len();
        for _ in 0..len {
            let next_context_lock = match contexts.pop_front() {
                Some(lock) => match lock.upgrade() {
                    Some(new_lock) => new_lock,
                    None => {
                        skipped_contexts += 1;
                        continue; // Ghost Process, just continue
                    }
                },
                None => break, // Empty Queue
            };

            if Arc::ptr_eq(&next_context_lock, &prev_context_lock) {
                contexts.push_back(ContextRef(Arc::clone(&next_context_lock)));
                continue;
            }

            let mut next_context_guard = unsafe { next_context_lock.write_arc() };
            next_context_guard.enqueued = false;

            if !next_context_guard.status.is_runnable() {
                skipped_contexts += 1;
                continue; // Lazy removal of blocked contexts
            }

            // Do not spawn the kernel (the idle context) again after idling,
            // otherwise the next switch will idling again
            if was_idle && !next_context_guard.userspace {
                continue;
            }

            // Is this context runnable on this CPU?
            if let UpdateResult::CanSwitch =
                unsafe { update_runnable(&mut next_context_guard, cpu_id, switch_time) }
            {
                next_context_guard_opt = Some(next_context_guard);
                balance[i] -= SCHED_PRIO_TO_WEIGHT[20];
                break 'priority;
            } else {
                contexts.push_back(ContextRef(Arc::clone(&next_context_lock)));
                next_context_guard.enqueued = true;
                skipped_contexts += 1;

                if skipped_contexts >= total_contexts {
                    break 'priority;
                }
            }
        }
    }
    percpu.balance.set(balance);
    percpu.last_queue.set(i);

    if let Some(next_context_guard) = next_context_guard_opt {
        // We found a new process!
        // Send the old process to the back of the line (if it is still runnable)
        if prev_context_guard.status.is_runnable() {
            let prio = prev_context_guard.prio;
            contexts_list[prio].push_back(ContextRef(Arc::clone(&prev_context_lock)));
            prev_context_guard.enqueued = true;
        }

        return Ok(Some(next_context_guard));
    } else {
        // We found no other process to run.
        Ok(None)
    }
}

/// Holds per-CPU state necessary for context switching.
///
/// This struct contains information such as the idle context, current context, and PIT tick counts,
/// as well as fields required for managing ptrace sessions and signals.
pub struct ContextSwitchPercpu {
    switch_result: Cell<Option<SwitchResultInner>>,
    switch_time: Cell<u128>,
    pit_ticks: Cell<usize>,

    current_ctxt: RefCell<Option<Arc<ContextLock>>>,

    pub(crate) being_sigkilled: Cell<bool>,
}

impl ContextSwitchPercpu {
    pub const fn default() -> Self {
        Self {
            switch_result: Cell::new(None),
            switch_time: Cell::new(0),
            pit_ticks: Cell::new(0),
            current_ctxt: RefCell::new(None),
            being_sigkilled: Cell::new(false),
        }
    }

    /// Applies a function to the current context, allowing controlled access.
    ///
    /// # Parameters
    /// - `f`: A closure that receives a reference to the current context and returns a value.
    ///
    /// # Returns
    /// The result of applying `f` to the current context.
    pub fn with_context<T>(&self, f: impl FnOnce(&Arc<ContextLock>) -> T) -> T {
        f(self
            .current_ctxt
            .borrow()
            .as_ref()
            .expect("not inside of context"))
    }

    /// Applies a function to the current context, allowing controlled access.
    ///
    /// # Parameters
    /// - `f`: A closure that receives a reference to the current context and returns a value.
    ///
    /// # Returns
    /// The result of applying `f` to the current context if any.
    pub fn try_with_context<T>(&self, f: impl FnOnce(Option<&Arc<ContextLock>>) -> T) -> T {
        f(self.current_ctxt.borrow().as_ref())
    }

    /// Sets the current context to a new value.
    ///
    /// # Safety
    /// This function is unsafe as it modifies the context state directly.
    ///
    /// # Parameters
    /// - `new`: The new context to be set as the current context.
    pub unsafe fn set_current_context(&self, new: Arc<ContextLock>) {
        *self.current_ctxt.borrow_mut() = Some(new);
    }
}
