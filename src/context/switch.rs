//! This module provides a context-switching mechanism that utilizes a simple round-robin scheduler.
//! The scheduler iterates over available contexts, selecting the next context to run, while
//! handling process states and synchronization.

use crate::{
    context::{
        self, arch, memory::AddrSpaceSwitchReadGuard, run_contexts, run_contexts_try,
        wakeup_context, ArcContextLockWriteGuard, Context, ContextLock, WeakContextRef,
    },
    cpu_set::LogicalCpuId,
    cpu_stats::{self, CpuState},
    percpu::PercpuBlock,
    sync::{ArcRwLockWriteGuard, CleanLockToken, L4},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    cmp::Reverse,
    hint, matches, mem,
    option::Option::{None, Some},
    sync::atomic::Ordering,
    u64,
};
use smallvec::SmallVec;
use spin::mutex::SpinMutex;
use syscall::PtraceFlags;

enum UpdateResult {
    CanSwitch,
    Skip,
    Blocked,
}

// A simple geometric series where value[i] ~= value[i + 1] * 1.25
pub const SCHED_PRIO_TO_WEIGHT: [usize; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

pub const SCALE: u128 = 1 << 40;
pub const TICK_INTERVAL: u64 = 3; // Approx 6.75 ms
pub const BASE_SLICE_TICKS: u64 = TICK_INTERVAL * 3; // Approx 20.25 ms
pub const NANOS_PER_TICK: u128 = 2_250_000; // 2.25 ms

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
        UpdateResult::Blocked
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
    if new_ticks >= TICK_INTERVAL as usize
        && arch::CONTEXT_SWITCH_LOCK.load(Ordering::Relaxed) == false
    {
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
    let mut wakeups: SmallVec<[(Option<u128>, WeakContextRef); 16]> = SmallVec::new();

    // These timers coukd have expired
    let mut timers: SmallVec<[(u128, WeakContextRef); 16]> = SmallVec::new();
    if let Some(mut run_contexts) = run_contexts_try(token.token()) {
        // Pop Timers
        while let Some((wake, _)) = run_contexts.timers.first() {
            if *wake > switch_time {
                break;
            }

            if let Some(entry) = run_contexts.timers.pop_first() {
                timers.push(entry);
            }
        }
    }

    for (wake, context_ref) in timers {
        let Some(context_lock) = context_ref.upgrade() else {
            continue;
        };

        let guard = context_lock.read(token.token());
        if guard.status.is_soft_blocked() && guard.wake == Some(wake) {
            wakeups.push((Some(wake), context_ref));
        }
    }

    // Drain from percpu
    {
        let mut cross_cpu_wake = percpu.switch_internals.cross_core_wakeup_list.lock();
        wakeups.extend(cross_cpu_wake.drain(..).map(|ctx| (None, ctx)));
    }
    {
        let mut local_wake = percpu.switch_internals.local_wakeup_list.borrow_mut();
        wakeups.extend(local_wake.drain(..).map(|ctx| (None, ctx)));
    }

    if wakeups.len() > 0 {
        let mut run_contexts = run_contexts(token.token());
        for (wake_opt, context_ref) in wakeups {
            let Some(context_lock) = context_ref.upgrade() else {
                continue;
            };

            let Some(mut guard) = (unsafe { context_lock.try_write_arc() }) else {
                if let Some(wake) = wake_opt {
                    run_contexts.timers.insert((wake, context_ref));
                } else {
                    percpu
                        .switch_internals
                        .local_wakeup_list
                        .borrow_mut()
                        .push(context_ref);
                }
                continue;
            };

            if let Some(wake) = wake_opt {
                if guard.status.is_soft_blocked() && guard.wake == Some(wake) {
                    guard.wake = None;
                    guard.unblock_no_ipi();
                }
            }

            if guard.running || !guard.status.is_runnable() {
                continue;
            }

            let new_vtime = guard.vtime.max(run_contexts.v);
            guard.vtime = new_vtime;

            let weight = SCHED_PRIO_TO_WEIGHT[guard.prio] as u64;
            let scaled_slice = (BASE_SLICE_TICKS as u128 * SCALE) / weight as u128;

            if !guard.is_active {
                guard.is_active = true;
                run_contexts.total_weight += weight;
            }

            if let Some(old_key) = guard.queue_key.take() {
                run_contexts.queue.remove(&old_key);
            }

            guard.vd = new_vtime + scaled_slice as u64;
            guard.rem_slice = BASE_SLICE_TICKS * SCALE as u64;
            let key = (guard.vd, Reverse(guard.rem_slice), guard.debug_id);
            guard.queue_key = Some(key);
            drop(guard);

            run_contexts
                .queue
                .insert(key, (new_vtime, weight, context_ref));
        }
    }

    /* // uncomment to debug contexts count
    let cpu_count = crate::cpu_count() as usize;
    let len_idle = idle_contexts(token.downgrade()).len();
    let all_contexts = context::contexts(token.downgrade())
        .len()
        .saturating_sub(cpu_count); // ignore kmain
    print!(
        "\r TIME {}.{} IDLE {} WAKEUPS {} ALL {} ",
        switch_time / 1000_000_000,
        (switch_time / 100_000_000) % 10,
        len_idle,
        wakeups_len,
        all_contexts
    );
    */

    let cpu_id = crate::cpu_id();

    // Update per-cpu times
    let percpu_nanos = switch_time.saturating_sub(percpu.switch_internals.switch_time.get()) as u64;
    let percpu_ms = percpu_nanos / 1_000_000;
    let was_idle = percpu.stats.add_time(percpu_ms) == CpuState::Idle as u8;
    percpu.switch_internals.switch_time.set(switch_time);

    let switch_context_opt = select_next_context(
        token,
        percpu,
        cpu_id,
        switch_time,
        percpu_nanos,
        was_idle,
        &mut prev_context_guard,
    );

    // Switch process states, TSS stack pointer, and store new context ID
    match switch_context_opt {
        Some((mut next_context_guard, addr_space_guard)) => {
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

            #[cfg(feature = "profiling")]
            {
                percpu
                    .switch_internals
                    .current_dbg_id
                    .store(next_context.debug_id, Ordering::Relaxed);
            }

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

            // Anything implement Drop must be manually dropped now
            drop(prev_context_lock);

            unsafe {
                percpu.new_addrsp_guard.set(addr_space_guard);
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

/// This is the scheduler function which currently utilises EEVDF Scheduler
fn select_next_context(
    token: &mut CleanLockToken,
    percpu: &PercpuBlock,
    cpu_id: LogicalCpuId,
    switch_time: u128,
    elapsed_time: u64,
    was_idle: bool,
    prev_context_guard: &mut ArcRwLockWriteGuard<L4, Context>,
) -> Option<(ArcContextLockWriteGuard, Option<AddrSpaceSwitchReadGuard>)> {
    let contexts_data = run_contexts(token.token());
    let (mut contexts_data, mut token) = contexts_data.into_split();
    let idle_context = percpu.switch_internals.idle_context();

    // Lock the previous context.
    let prev_context_lock = crate::context::current();
    let is_idle = Arc::ptr_eq(&prev_context_lock, &idle_context);
    let prev_runnable = !is_idle && prev_context_guard.status.is_runnable();
    let is_timer = prev_context_guard.wake.is_some();

    let elapsed_ticks = elapsed_time as u128 * SCALE / NANOS_PER_TICK;

    if prev_runnable {
        let weight = SCHED_PRIO_TO_WEIGHT[prev_context_guard.prio] as u64;
        prev_context_guard.rem_slice = prev_context_guard
            .rem_slice
            .saturating_sub((elapsed_ticks) as u64);
        let scaled_task = elapsed_ticks / weight as u128;
        prev_context_guard.vtime += scaled_task as u64;

        if prev_context_guard.vtime < contexts_data.v {
            prev_context_guard.vtime = contexts_data.v;
        }

        let is_yield = (elapsed_time as u128) < (TICK_INTERVAL as u128 * NANOS_PER_TICK) / 2;

        if is_yield {
            let unconsumed = prev_context_guard.rem_slice as u128;
            let penalty = unconsumed / weight as u128;
            prev_context_guard.vtime += penalty as u64;
            prev_context_guard.rem_slice = 0;
        }

        if prev_context_guard.rem_slice == 0 {
            prev_context_guard.rem_slice = BASE_SLICE_TICKS * SCALE as u64;
            let scaled_slice = (BASE_SLICE_TICKS as u128 * SCALE) / weight as u128;
            prev_context_guard.vd = prev_context_guard.vtime + scaled_slice as u64;
        }
    } else if !is_idle {
        if prev_context_guard.is_active {
            prev_context_guard.is_active = false;
            let weight = SCHED_PRIO_TO_WEIGHT[prev_context_guard.prio] as u64;
            contexts_data.total_weight = contexts_data.total_weight.saturating_sub(weight);
        }
        prev_context_guard.rem_slice = 0;

        if let Some(wake) = prev_context_guard.wake {
            contexts_data
                .timers
                .insert((wake, WeakContextRef(Arc::downgrade(&prev_context_lock))));
        }
    }

    let mut eligible_best = None;
    let mut prev_is_eligible = false;

    let mut ineligible_best = None;
    let mut ineligible_min_vtime = u64::MAX;
    let mut ineligible_vd = u64::MAX;

    if prev_runnable {
        if prev_context_guard.vtime <= contexts_data.v {
            prev_is_eligible = true;
        } else {
            ineligible_min_vtime = prev_context_guard.vtime;
            ineligible_vd = prev_context_guard.vd;
        }
    }

    // New BTreeMap based walk
    let mut weight_change: u64 = 0;
    let mut contexts_to_remove: SmallVec<[(u64, Reverse<u64>, u32); 16]> = SmallVec::new();
    for ((vd, rem_slice, ctxt_id), (vtime, context_weight, context_ref)) in
        contexts_data.queue.iter()
    {
        if *vtime > ineligible_min_vtime && *vtime > contexts_data.v {
            continue;
        }

        let Some(context_lock) = context_ref.upgrade() else {
            weight_change += *context_weight as u64;
            contexts_to_remove.push((*vd, *rem_slice, *ctxt_id));
            continue;
        };

        if Arc::ptr_eq(&context_lock, &idle_context)
            || Arc::ptr_eq(&context_lock, &prev_context_lock)
        {
            //weight_change += *context_weight as u64;
            //contexts_to_remove.push((*vd, *rem_slice, *ctxt_id));
            continue;
        }

        let Some(mut guard) = (unsafe { context_lock.try_write_arc() }) else {
            continue;
        };

        let sw = unsafe { update_runnable(&mut guard, cpu_id, switch_time) };

        if matches!(sw, UpdateResult::Blocked) {
            if guard.is_active {
                guard.is_active = false;
                weight_change += context_weight;
            }
            guard.rem_slice = 0;
            guard.queue_key = None;

            contexts_to_remove.push((*vd, *rem_slice, *ctxt_id));
            drop(guard);
            continue;
        }

        if !matches!(sw, UpdateResult::CanSwitch) {
            continue;
        }

        let mut best_addr_space = None;
        if let Some(addr_space) = &guard.addr_space {
            let mut t = unsafe { CleanLockToken::new() };
            if let Some(addr) = addr_space.inner.try_read(t.token()) {
                best_addr_space = Some(AddrSpaceSwitchReadGuard::new(addr));
            } else {
                continue;
            }
        }

        if *vtime <= contexts_data.v {
            // Eligible
            eligible_best = Some((guard, best_addr_space));
            break;
        } else {
            // Ineligible
            if *vtime < ineligible_min_vtime {
                ineligible_min_vtime = *vtime;
                ineligible_vd = *vd;
                if let Some((old_guard, old_addr_space)) = ineligible_best {
                    drop(old_guard);
                    drop(old_addr_space);
                }
                ineligible_best = Some((guard, best_addr_space));
            }
        }
    }

    contexts_data.total_weight = contexts_data.total_weight.saturating_sub(weight_change);

    for old_key in contexts_to_remove {
        contexts_data.queue.remove(&old_key);
    }

    // No eligible context was found
    if !(prev_is_eligible || eligible_best.is_some()) && ineligible_min_vtime != u64::MAX {
        contexts_data.v = ineligible_min_vtime; // Advance V

        let prev_is_earliest = prev_runnable && prev_context_guard.vtime <= ineligible_min_vtime;

        if prev_is_earliest {
            eligible_best = None;
        } else if ineligible_best.is_some() {
            let prev_has_slice = prev_runnable && prev_context_guard.rem_slice > 0;

            if prev_has_slice && prev_context_guard.vd <= ineligible_vd {
                eligible_best = None;
            } else {
                eligible_best = ineligible_best.take();
            }
        }
    } else if prev_is_eligible && eligible_best.is_some() {
        if let Some((ref guard, _)) = eligible_best {
            if prev_context_guard.vd < guard.vd
                || (prev_context_guard.vd == guard.vd
                    && prev_context_guard.rem_slice > guard.rem_slice)
            {
                eligible_best = None;
            }
        }
    }

    let mut final_winner = None;

    if let Some((mut chosen_guard, addr_space)) = eligible_best {
        if let Some(key) = chosen_guard.queue_key.take() {
            contexts_data.queue.remove(&key);
        }
        final_winner = Some((chosen_guard, addr_space));
    }

    if final_winner.is_some() || prev_runnable {
        if contexts_data.total_weight > 0 {
            let v_advance = elapsed_ticks as u128 / contexts_data.total_weight as u128;
            contexts_data.v += v_advance as u64;
        }

        if let Some((chosen_guard, addr_space)) = final_winner {
            if prev_runnable {
                let (vd, rem_slice, ctxt_id, vtime) = (
                    prev_context_guard.vd,
                    prev_context_guard.rem_slice,
                    prev_context_guard.debug_id,
                    prev_context_guard.vtime,
                );

                if let Some(old_key) = prev_context_guard.queue_key.take() {
                    contexts_data.queue.remove(&old_key);
                }

                prev_context_guard.queue_key = Some((vd, Reverse(rem_slice), ctxt_id));

                let weight = SCHED_PRIO_TO_WEIGHT[prev_context_guard.prio] as u64;
                contexts_data.queue.insert(
                    (vd, Reverse(rem_slice), ctxt_id),
                    (
                        vtime,
                        weight,
                        WeakContextRef(Arc::downgrade(&prev_context_lock)),
                    ),
                );
            }

            return Some((chosen_guard, addr_space));
        } else {
            return None;
        }
    } else {
        let prev_is_dead = !is_idle && !prev_context_guard.status.is_runnable();
        if (!was_idle || prev_is_dead) && !is_idle {
            return Some(unsafe { (idle_context.write_arc(), None) });
        } else {
            return None;
        }
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

    // TODO: just access current_ctxt directly?
    #[cfg(feature = "profiling")]
    pub(crate) current_dbg_id: core::sync::atomic::AtomicU32,

    /// The idle process.
    idle_ctxt: RefCell<Option<Arc<ContextLock>>>,
    pub(crate) being_sigkilled: Cell<bool>,

    // wakeups
    pub(crate) cross_core_wakeup_list: SpinMutex<Vec<WeakContextRef>>,
    pub(crate) local_wakeup_list: RefCell<Vec<WeakContextRef>>,
}

impl ContextSwitchPercpu {
    pub const fn default() -> Self {
        Self {
            switch_result: Cell::new(None),
            switch_time: Cell::new(0),
            pit_ticks: Cell::new(0),
            current_ctxt: RefCell::new(None),
            idle_ctxt: RefCell::new(None),
            being_sigkilled: Cell::new(false),
            cross_core_wakeup_list: SpinMutex::new(Vec::new()),
            local_wakeup_list: RefCell::new(Vec::new()),

            #[cfg(feature = "profiling")]
            current_dbg_id: core::sync::atomic::AtomicU32::new(!0),
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

    /// Sets the idle context to a new value.
    ///
    /// # Safety
    /// This function is unsafe as it modifies the idle context state directly.
    ///
    /// # Parameters
    /// - `new`: The new context to be set as the idle context.
    pub unsafe fn set_idle_context(&self, new: Arc<ContextLock>) {
        *self.idle_ctxt.borrow_mut() = Some(new);
    }

    /// Retrieves the current idle context.
    ///
    /// # Returns
    /// A reference to the idle context.
    pub fn idle_context(&self) -> Arc<ContextLock> {
        Arc::clone(
            self.idle_ctxt
                .borrow()
                .as_ref()
                .expect("no idle context present"),
        )
    }
}
