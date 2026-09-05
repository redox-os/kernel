//! This module provides a context-switching mechanism that utilizes a simple round-robin scheduler.
//! The scheduler iterates over available contexts, selecting the next context to run, while
//! handling process states and synchronization.

// TODO(refactor): split this module into a scheduler and a switch module

use crate::{
    context::{
        self, arch, memory::AddrSpaceSwitchReadGuard, wakeup_context, ArcContextLockWriteGuard,
        Context, ContextLock, RunContextData, WeakContextRef,
    },
    cpu_set::LogicalCpuId,
    cpu_stats::{self, CpuState},
    percpu::{self, get_percpu_block, PercpuBlock},
    scheme::serio::DEBUG_ENABLE,
    sync::{ArcRwLockWriteGuard, CleanLockToken, Mutex, L4},
};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    cell::{Cell, Ref, RefCell},
    cmp::Reverse,
    hint, matches, mem,
    option::Option::{None, Some},
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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

pub const SCALE: u128 = 1 << 30;
pub const TICK_INTERVAL: u64 = 3; // Approx 6.75 ms
pub const BASE_SLICE_TICKS: u64 = TICK_INTERVAL * 3; // Approx 20.25 ms
pub const NANOS_PER_TICK: u128 = 2_250_000; // 2.25 ms
pub const STEAL_THRESHOLD: usize = 2;
pub const STEAL_INTERVAL: usize = 2;
pub const MAX_STEAL: usize = 2;

/// Determines if a given context is eligible to be scheduled on a given CPU (in
/// principle, the current CPU).
///
/// # Parameters
/// - `context`: The context (process/thread) to be checked.
/// - `cpu_id`: The logical ID of the CPU on which the context is being scheduled.
///
/// # Returns
/// - `UpdateResult::CanSwitch`: If the context can be switched to.
/// - `UpdateResult::Skip`: If the context should be skipped (e.g., it's running on another CPU).
fn update_runnable(
    context: &mut Context,
    cpu_id: LogicalCpuId,
    schedule_time: u128,
    next_is_current_sched: bool,
) -> UpdateResult {
    // Ignore contexts that are already running.
    if context.running {
        return UpdateResult::Skip;
    }

    // Ignore contexts that are currently scheduled, unless scheduled on the current hardware
    // thread.
    if context.currently_scheduled && !next_is_current_sched {
        return UpdateResult::Skip;
    }

    // Ignore contexts assigned to other CPUs.
    if !context.sched_affinity.contains(cpu_id) {
        return UpdateResult::Skip;
    }

    // If context is soft-blocked and has a wake-up time, check if it should wake up.
    if context.status.is_soft_blocked()
        && let Some(wake) = context.wake
        && schedule_time >= wake
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
    if new_ticks >= TICK_INTERVAL as usize {
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
        crate::percpu::switch_arch_hook();
    }
}

/// Drains the cross_cpu_wakeup_list into local_wakeup_list.
/// This is called from the ipi handler.
pub fn drain_ipi_context_wakeups(token: &mut CleanLockToken) {
    let percpu = PercpuBlock::current();
    let mut cross_cpu_wake = percpu
        .switch_internals
        .ipi_context_wakeup_list
        .lock(token.token());
    if cross_cpu_wake.is_empty() {
        return;
    }

    let mut local_wake = percpu.switch_internals.local_wakeup_list.borrow_mut();
    local_wake.extend(cross_cpu_wake.drain(..));
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
    let percpu = PercpuBlock::current();
    let schedule_time = crate::time::monotonic(token);

    switch_inner(percpu, schedule_time, token)
}
fn switch_inner(
    percpu: &PercpuBlock,
    schedule_time: u128,
    token: &mut CleanLockToken,
) -> SwitchResult {
    if DEBUG_ENABLE.load(Ordering::Relaxed) {
        //info!("NEW SWITCH");
    }

    if try_direct_switch_back(percpu, schedule_time, token) {
        /*if DEBUG_ENABLE.load(Ordering::Relaxed) {
            info!("RETURN FROM DIRECT SWITCH BACK");
        }*/
        return SwitchResult::Switched;
    }

    let (prev_sched_guard, next_sched_guard, next_addrsp_guard, schedule_time) =
        match schedule(percpu, schedule_time, token) {
            ScheduleResult::Picked {
                prev_sched_context,
                next_sched_context,
                next_address_space,
                schedule_time,
            } => (
                prev_sched_context,
                next_sched_context,
                next_address_space,
                schedule_time,
            ),
            // didn't change sched context, so will not change current context
            ScheduleResult::AllContextsIdle => {
                percpu.stats.set_state(cpu_stats::CpuState::Idle);

                return SwitchResult::AllContextsIdle;
            }
        };
    /*if DEBUG_ENABLE.load(Ordering::Relaxed) {
        info!("===============");
        info!(
            "REGULAR SWITCHING `{}` => `{}`",
            prev_sched_guard.name, next_sched_guard.name
        );
        info!(
            "STATUSES `{:?}` => `{:?}`",
            prev_sched_guard.status, next_sched_guard.status
        );
        info!(
            "ADDRESSES `{:p}` => `{:p}`",
            Arc::as_ptr(ArcContextLockWriteGuard::rwlock(&prev_sched_guard)),
            Arc::as_ptr(ArcContextLockWriteGuard::rwlock(&next_sched_guard))
        );
        info!("---------------");
        info!("RQ {:?}", percpu.switch_internals.run_queue);
        info!(
            "WK: IPI {:?} LOCAL {:?}",
            percpu.switch_internals.ipi_context_wakeup_list,
            percpu.switch_internals.local_wakeup_list
        );
        info!(
            "CUR {:x} SCHED {:x}",
            percpu
                .switch_internals
                .current_ctxt
                .borrow()
                .as_ref()
                .map_or(0, |c| Arc::as_ptr(c) as usize),
            percpu
                .switch_internals
                .sched_ctxt
                .borrow()
                .as_ref()
                .map_or(0, |c| Arc::as_ptr(c) as usize)
        );
        info!("===============");
    }
    */

    let current_context_lock_ref = percpu.switch_internals.current_context();

    if Arc::ptr_eq(
        &*current_context_lock_ref,
        ArcContextLockWriteGuard::rwlock(&next_sched_guard),
    ) {
        // We had already switched the current context to the one now picked by the scheduler, so
        // no switch needs to be done.
        return SwitchResult::Switched;
    }
    let current_context_guard = if Arc::ptr_eq(
        &*current_context_lock_ref,
        ArcContextLockWriteGuard::rwlock(&prev_sched_guard),
    ) {
        // The previous sched and previous current contexts coincided.
        // TODO: s/current/real/g
        prev_sched_guard
    } else {
        drop(prev_sched_guard);
        unsafe { current_context_lock_ref.write_arc() }
    };

    let was_idle = Arc::ptr_eq(
        &current_context_lock_ref,
        percpu.switch_internals.idle_ctxt.borrow().as_ref().unwrap(),
    );
    drop(current_context_lock_ref);

    let switch_time = schedule_time;

    unsafe {
        switch_to(
            percpu,
            current_context_guard,
            next_sched_guard,
            next_addrsp_guard,
            switch_time,
            was_idle,
        );
    }

    SwitchResult::Switched
}
enum ScheduleResult {
    Picked {
        prev_sched_context: ArcContextLockWriteGuard,
        next_sched_context: ArcContextLockWriteGuard,
        next_address_space: Option<AddrSpaceSwitchReadGuard>,
        schedule_time: u128,
    },
    AllContextsIdle,
}

// There's a separation between the sched context and current context: the former context is the
// owner of the current timeslice, and may be blocked or even Dead, whereas the latter is the
// context whose state the CPU and the rest of the kernel is currently "configured to run" (e.g.
// address space, registers). This function only modifies the sched context.
//
// Unless the new sched context is the current context (i.e. context A holds the timeslice,
// direct-switches to B, A's timeslice expires, and the scheduler picked B), the caller should then
// *switch* to the new context.
fn schedule(
    percpu: &PercpuBlock,
    schedule_time: u128,
    token: &mut CleanLockToken,
) -> ScheduleResult {
    percpu.stats.add_context_switch(percpu.inside_syscall.get());

    //set PIT Interrupt counter to 0, giving each process same amount of PIT ticks
    percpu.switch_internals.pit_ticks.set(0);

    #[cfg(target_arch = "aarch64")]
    let mut lock_stall_watch = crate::arch::misc::StallWatch::start(2);

    // Lock the previous (sched) context.
    let mut prev_context_guard = {
        let lock_ref = percpu.switch_internals.sched_context();
        // We are careful not to lock this context twice
        unsafe { lock_ref.write_arc() }
    };
    let prev_context_ptr = Arc::as_ptr(ArcContextLockWriteGuard::rwlock(&prev_context_guard));
    let cur_context_ptr = Arc::as_ptr(&*percpu.switch_internals.current_context());

    /*
    if !prev_context_guard.is_preemptable() {
        // Pretend to have finished switching, so CPU is not idled
        return ScheduleResult::Switched;
    }
    */

    {
        // Alarm (previously in update_runnable)
        let mut wakeups = percpu.switch_internals.tmp_wakeups.borrow_mut();

        // These timers coukd have expired
        let mut timers = percpu.switch_internals.tmp_timers.borrow_mut();
        timers.clear();
        {
            let mut run_queue = percpu.switch_internals.run_queue.lock();
            let split_key = (schedule_time.saturating_add(1), WeakContextRef(Weak::new()));

            timers.extend(run_queue.timers.extract_if(..split_key, |_| true));
        }

        timers.retain(|(wake, context_ref)| {
            let Some(context_lock) = context_ref.upgrade() else {
                return false;
            };

            if let Some(guard) = context_lock.try_read(token.token()) {
                if guard.status.is_soft_blocked() && guard.wake == Some(*wake) {
                    wakeups.push((Some(*wake), context_ref.clone()));
                }
                false
            } else {
                true
            }
        });

        // Drain from percpu
        {
            let mut local_wake = percpu.switch_internals.local_wakeup_list.borrow_mut();
            wakeups.extend(local_wake.drain(..).map(|ctx| (None, ctx)));
        }

        if !wakeups.is_empty() {
            let mut run_queue = percpu.switch_internals.run_queue.lock();
            for (wake_opt, context_ref) in wakeups.drain(..) {
                let context_ptr = Weak::as_ptr(&context_ref.0);

                if context_ptr == prev_context_ptr {
                    continue;
                }

                let Some(context_lock) = context_ref.upgrade() else {
                    continue;
                };

                let Some(mut guard) = (unsafe { context_lock.try_write_arc() }) else {
                    if let Some(wake) = wake_opt {
                        run_queue.timers.insert((wake, context_ref));
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

                // Non-runnable contexts should obviously not be pushed to the runqueue.
                //
                // Currently scheduled contexts shouldn't either, as they must by construction be
                // scheduled on another thread (otherwise guard and prev_context_guard would be the
                // same object, which is also forbidden).
                if !guard.status.is_runnable() || guard.currently_scheduled {
                    continue;
                }

                // Nor should runnable contexts, except when it was runnable only because it was
                // directly-switched to temporarily, from a different sched context.
                if guard.running
                    && !(context_ptr == cur_context_ptr && context_ptr != prev_context_ptr)
                {
                    continue;
                }

                let new_vtime = guard.vtime.max(run_queue.v);
                guard.vtime = new_vtime;

                let weight = SCHED_PRIO_TO_WEIGHT[guard.prio] as u64;
                let scaled_slice = (BASE_SLICE_TICKS as u128 * SCALE) / weight as u128;

                if !guard.is_active {
                    guard.is_active = true;
                    run_queue.total_weight += weight;
                    percpu
                        .switch_internals
                        .total_weight
                        .store(run_queue.total_weight, Ordering::Relaxed);
                }

                if let Some(old_key) = guard.queue_key.take() {
                    run_queue.queue.remove(&old_key);
                    percpu
                        .switch_internals
                        .queue_len
                        .store(run_queue.queue.len(), Ordering::Relaxed);
                }

                guard.vd = new_vtime + scaled_slice as u64;
                guard.rem_slice = BASE_SLICE_TICKS * SCALE as u64;
                let key = (guard.vd, Reverse(guard.rem_slice), guard.debug_id);
                guard.queue_key = Some(key);
                drop(guard);

                run_queue
                    .queue
                    .insert(key, (new_vtime, weight, context_ref));
                percpu
                    .switch_internals
                    .queue_len
                    .store(run_queue.queue.len(), Ordering::Relaxed);
            }
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
        schedule_time / 1000_000_000,
        (schedule_time / 100_000_000) % 10,
        len_idle,
        wakeups_len,
        all_contexts
    );
    */

    // Update per-cpu times
    let percpu_nanos =
        schedule_time.saturating_sub(percpu.switch_internals.schedule_time.get()) as u64;
    let percpu_ms = percpu_nanos / 1_000_000;
    let was_idle = percpu.stats.add_time(percpu_ms) == CpuState::Idle as u8;
    percpu.switch_internals.schedule_time.set(schedule_time);

    let Some((mut next_sched_context, next_address_space)) = select_next_context(
        percpu,
        percpu.cpu_id,
        schedule_time,
        percpu_nanos,
        was_idle,
        &mut prev_context_guard,
    ) else {
        return ScheduleResult::AllContextsIdle;
    };

    *percpu.switch_internals.sched_ctxt.borrow_mut() = Some(Arc::clone(
        ArcContextLockWriteGuard::rwlock(&next_sched_context),
    ));

    prev_context_guard.currently_scheduled = false;
    next_sched_context.currently_scheduled = true;

    if !was_idle {
        prev_context_guard.sched_cpu_time +=
            schedule_time.saturating_sub(prev_context_guard.schedule_time);
    }

    ScheduleResult::Picked {
        prev_sched_context: prev_context_guard,
        next_sched_context,
        next_address_space,
        schedule_time,
    }
}

/// This is the scheduler function which currently utilises EEVDF Scheduler
fn select_next_context(
    percpu: &PercpuBlock,
    cpu_id: LogicalCpuId,
    schedule_time: u128,
    elapsed_time: u64,
    was_idle: bool,
    prev_context_guard: &mut ArcRwLockWriteGuard<L4, Context>,
) -> Option<(ArcContextLockWriteGuard, Option<AddrSpaceSwitchReadGuard>)> {
    let mut contexts_data = percpu.switch_internals.run_queue.lock();
    let idle_context = percpu.switch_internals.idle_context();

    // Lock the previous context.
    let prev_context_lock = Arc::clone(ArcRwLockWriteGuard::rwlock(prev_context_guard));
    let is_idle = Arc::ptr_eq(&prev_context_lock, &idle_context);
    let prev_runnable = !is_idle && prev_context_guard.status.is_runnable();

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

        let next_is_current_sched = Arc::ptr_eq(&context_lock, &prev_context_lock);

        if Arc::ptr_eq(&context_lock, &idle_context) || next_is_current_sched {
            continue;
        }

        let Some(mut guard) = (unsafe { context_lock.try_write_arc() }) else {
            continue;
        };

        // next_is_current_sched is false by the above check
        let sw = update_runnable(&mut guard, cpu_id, schedule_time, next_is_current_sched);

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
                best_addr_space = Some(unsafe { AddrSpaceSwitchReadGuard::new(addr) });
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
    percpu
        .switch_internals
        .total_weight
        .store(contexts_data.total_weight, Ordering::Relaxed);

    for old_key in contexts_to_remove {
        contexts_data.queue.remove(&old_key);
    }
    percpu
        .switch_internals
        .queue_len
        .store(contexts_data.queue.len(), Ordering::Relaxed);

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
            percpu
                .switch_internals
                .queue_len
                .store(contexts_data.queue.len(), Ordering::Relaxed);
        }
        final_winner = Some((chosen_guard, addr_space));
    }

    // Work Stealing
    {
        let local_len = contexts_data.queue.len();
        let num_cpu = crate::cpu_count();
        let curr_cpu = cpu_id.get();

        let counter = percpu
            .switch_internals
            .steal_counter
            .fetch_add(1, Ordering::Relaxed)
            % STEAL_INTERVAL;

        let mut steal_hint = None;
        let should_steal = local_len == 0
            || (counter == 0 && {
                let mut max_neighbour = 0;

                for i in 0..num_cpu {
                    if i == curr_cpu {
                        continue;
                    }

                    if let Some(p) = get_percpu_block(LogicalCpuId::new(i as u32)) {
                        let neighbour_len = p.switch_internals.queue_len.load(Ordering::Relaxed);

                        if neighbour_len > max_neighbour {
                            max_neighbour = neighbour_len;
                            steal_hint = Some(i);
                        }
                    }
                }

                max_neighbour > local_len.saturating_add(STEAL_THRESHOLD)
            });

        if should_steal {
            let targets = steal_hint
                .into_iter()
                .chain((1..num_cpu).map(|i| (curr_cpu + i) % num_cpu));

            for target_cpu in targets {
                if target_cpu == curr_cpu {
                    continue;
                }
                let Some(target_percpu) = get_percpu_block(LogicalCpuId::new(target_cpu)) else {
                    continue;
                };

                if !target_percpu
                    .switch_internals
                    .stealable
                    .load(Ordering::Relaxed)
                {
                    continue;
                }

                let Some(mut target_queue) = target_percpu.switch_internals.run_queue.try_lock()
                else {
                    continue;
                };

                let target_len = target_queue.queue.len();

                let extra = target_len.saturating_sub(contexts_data.queue.len());
                if extra < 2 {
                    continue;
                }

                let want = (extra / 2).clamp(1, MAX_STEAL);

                let mut stolen = percpu.switch_internals.tmp_steal.borrow_mut();
                stolen.clear();

                for (key, (_, weight, context_ref)) in target_queue.queue.iter().step_by(2) {
                    if stolen.len() >= want {
                        break;
                    }

                    let Some(context_lock) = context_ref.upgrade() else {
                        continue;
                    };

                    let Some(guard) = (unsafe { context_lock.try_write_arc() }) else {
                        continue;
                    };

                    if !guard.sched_affinity.contains(cpu_id)
                        || !guard.status.is_runnable()
                        || guard.running
                        || guard.currently_scheduled
                    {
                        continue;
                    }

                    let mut best_addr_space = None;
                    if let Some(addr_space) = &guard.addr_space {
                        let mut t = unsafe { CleanLockToken::new() };
                        match addr_space.inner.try_read(t.token()) {
                            Some(addr) => {
                                best_addr_space =
                                    Some(unsafe { AddrSpaceSwitchReadGuard::new(addr) })
                            }
                            None => continue,
                        }
                    }

                    stolen.push((*key, *weight, context_ref.clone(), guard, best_addr_space));
                }

                if stolen.is_empty() {
                    continue;
                }

                for (key, weight, context_ref, mut guard, addr_space) in stolen.drain(..) {
                    target_queue.queue.remove(&key);
                    target_queue.total_weight = target_queue.total_weight.saturating_sub(weight);
                    guard.queue_key = None;

                    let offset = guard.vtime as i128 - target_queue.v as i128;
                    guard.vtime = (contexts_data.v as i128 + offset).max(0) as u64;

                    let scaled_slice = guard.rem_slice / weight;
                    guard.vd = guard.vtime.saturating_add(scaled_slice);

                    if final_winner.is_none() && !prev_runnable {
                        final_winner = Some((guard, addr_space));
                    } else {
                        let new_key = (guard.vd, Reverse(guard.rem_slice), guard.debug_id);
                        guard.queue_key = Some(new_key);
                        contexts_data.total_weight =
                            contexts_data.total_weight.saturating_add(weight);
                        contexts_data
                            .queue
                            .insert(new_key, (guard.vtime, weight, context_ref));
                    }
                }

                percpu
                    .switch_internals
                    .total_weight
                    .store(contexts_data.total_weight, Ordering::Relaxed);
                percpu
                    .switch_internals
                    .queue_len
                    .store(contexts_data.queue.len(), Ordering::Relaxed);

                target_percpu
                    .switch_internals
                    .queue_len
                    .store(target_queue.queue.len(), Ordering::Relaxed);
                target_percpu
                    .switch_internals
                    .total_weight
                    .store(target_queue.total_weight, Ordering::Relaxed);
                target_percpu
                    .switch_internals
                    .stealable
                    .store(!target_queue.queue.is_empty(), Ordering::Relaxed);

                break;
            }
        }
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
                    percpu
                        .switch_internals
                        .queue_len
                        .store(contexts_data.queue.len(), Ordering::Relaxed);
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
                percpu
                    .switch_internals
                    .queue_len
                    .store(contexts_data.queue.len(), Ordering::Relaxed);
            }

            percpu
                .switch_internals
                .stealable
                .store(!contexts_data.queue.is_empty(), Ordering::Relaxed);

            /*if DEBUG_ENABLE.load(Ordering::Relaxed) {
                info!("SOME; FINAL WINNER SOME");
            }*/
            return Some((chosen_guard, addr_space));
        } else {
            percpu
                .switch_internals
                .stealable
                .store(!contexts_data.queue.is_empty(), Ordering::Relaxed);
            /*if DEBUG_ENABLE.load(Ordering::Relaxed) {
                info!("NONE; FINAL WINNER SOME");
            }*/
            return None;
        }
    } else {
        let prev_is_dead = !is_idle && !prev_context_guard.status.is_runnable();

        percpu
            .switch_internals
            .stealable
            .store(!contexts_data.queue.is_empty(), Ordering::Relaxed);

        if (!was_idle || prev_is_dead) && !is_idle {
            /*if DEBUG_ENABLE.load(Ordering::Relaxed) {
                info!("SOME; FINAL WINNER NONE");
            }*/

            // Since the idle context is per-cpu, then assuming its context Arc will only be
            // accessed by a "leaf" that doesn't acquire the runqueue (such as the sys scheme), it
            // should be safe to use a blocking write acquire here.
            return Some(unsafe { (idle_context.write_arc(), None) });
        } else {
            /*if DEBUG_ENABLE.load(Ordering::Relaxed) {
                //info!("NONE; FINAL WINNER NONE");
            }*/
            return None;
        }
    }
}

/// try to switch back from current_ctxt to sched_ctxt
fn try_direct_switch_back(
    percpu: &PercpuBlock,
    schedule_time: u128,
    token: &mut CleanLockToken,
) -> bool {
    let (mut prev_guard, mut next_guard) = {
        let current = Ref::map(percpu.switch_internals.current_ctxt.borrow(), |c| {
            c.as_ref().expect("no current context")
        });
        let sched = Ref::map(percpu.switch_internals.sched_ctxt.borrow(), |c| {
            c.as_ref().expect("no sched context")
        });

        // Not meaningful to switch back to itself.
        if Arc::ptr_eq(&current, &sched) {
            return false;
        }

        let next_lock = Arc::clone(&sched);
        let prev_lock = Arc::clone(&current);

        (unsafe { prev_lock.write_arc() }, unsafe {
            next_lock.write_arc()
        })
    };

    /*if DEBUG_ENABLE.load(Ordering::Relaxed) {
        info!(
            "TRYING, STATUSES {:?} => {:?}",
            prev_guard.status, next_guard.status
        );
    }*/

    // True by definition, as we pick sched_ctxt specifically to switch back to.
    let next_is_current_sched = true;

    if !matches!(
        update_runnable(
            &mut *next_guard,
            percpu.cpu_id,
            schedule_time,
            next_is_current_sched, // necessarily true
        ),
        UpdateResult::CanSwitch
    ) {
        return false;
    }
    /*if DEBUG_ENABLE.load(Ordering::Relaxed) {
        info!("===============");
        info!(
            "SWITCHING BACK `{}` => `{}`",
            prev_guard.name, next_guard.name
        );
        info!(
            "STATUSES `{:?}` => `{:?}`",
            prev_guard.status, next_guard.status
        );
        info!(
            "ADDRESSES `{:p}` => `{:p}`",
            Arc::as_ptr(ArcContextLockWriteGuard::rwlock(&prev_guard)),
            Arc::as_ptr(ArcContextLockWriteGuard::rwlock(&next_guard))
        );
        info!("---------------");
        info!("RQ {:?}", percpu.switch_internals.run_queue);
        info!(
            "WK: IPI {:?} LOCAL {:?}",
            percpu.switch_internals.ipi_context_wakeup_list,
            percpu.switch_internals.local_wakeup_list
        );
        info!(
            "CUR {:x} SCHED {:x}",
            percpu
                .switch_internals
                .current_ctxt
                .borrow()
                .as_ref()
                .map_or(0, |c| Arc::as_ptr(c) as usize),
            percpu
                .switch_internals
                .sched_ctxt
                .borrow()
                .as_ref()
                .map_or(0, |c| Arc::as_ptr(c) as usize)
        );
        info!("===============");
    }*/

    let addr_space = next_guard
        .addr_space()
        .ok()
        .map(|addrsp| unsafe { AddrSpaceSwitchReadGuard::new(addrsp.inner.read(token.token())) });

    let was_idle = Arc::ptr_eq(
        &ArcContextLockWriteGuard::rwlock(&prev_guard),
        percpu.switch_internals.idle_ctxt.borrow().as_ref().unwrap(),
    );

    unsafe {
        switch_to(
            percpu,
            prev_guard,
            next_guard,
            addr_space,
            schedule_time,
            was_idle,
        );
    }

    true
}

pub fn direct_switch_to(
    next_context: Arc<ContextLock>,
    token: &mut CleanLockToken,
) -> SwitchResult {
    let schedule_time = crate::time::monotonic(token);

    let percpu = PercpuBlock::current();
    let (prev_context_guard, prev_context_ptr) = {
        let prev_context_ref = context::current();

        // TODO: should this panic?
        if Arc::ptr_eq(&*prev_context_ref, &next_context) {
            return SwitchResult::Switched;
        }

        assert!(!Arc::ptr_eq(
            &*prev_context_ref,
            &percpu.switch_internals.idle_context()
        ));

        (
            unsafe { prev_context_ref.write_arc() },
            Arc::as_ptr(&*prev_context_ref),
        )
    };
    let was_idle = prev_context_ptr
        == Arc::as_ptr(percpu.switch_internals.idle_ctxt.borrow().as_ref().unwrap());

    let mut next_context_guard = unsafe { next_context.write_arc() };

    /*if DEBUG_ENABLE.load(Ordering::Relaxed) {
        info!("===============");
        info!(
            "DIRECT SWITCHING `{}` => `{}`",
            prev_context_guard.name, next_context_guard.name
        );
        info!(
            "STATUSES `{:?}` => `{:?}`",
            prev_context_guard.status, next_context_guard.status
        );
        info!(
            "ADDRESSES `{:p}` => `{:p}`",
            Arc::as_ptr(ArcContextLockWriteGuard::rwlock(&prev_context_guard)),
            Arc::as_ptr(ArcContextLockWriteGuard::rwlock(&next_context_guard))
        );
        info!("---------------");
        info!("RQ {:?}", percpu.switch_internals.run_queue);
        info!(
            "WK: IPI {:?} LOCAL {:?}",
            percpu.switch_internals.ipi_context_wakeup_list,
            percpu.switch_internals.local_wakeup_list
        );
        info!(
            "CUR {:x} SCHED {:x}",
            percpu
                .switch_internals
                .current_ctxt
                .borrow()
                .as_ref()
                .map_or(0, |c| Arc::as_ptr(c) as usize),
            percpu
                .switch_internals
                .sched_ctxt
                .borrow()
                .as_ref()
                .map_or(0, |c| Arc::as_ptr(c) as usize)
        );
        info!("===============");
    }*/

    let next_is_current_sched = Arc::ptr_eq(
        &percpu
            .switch_internals
            .sched_ctxt
            .borrow()
            .as_ref()
            .expect("no sched ctxt"),
        &next_context,
    );

    if !matches!(
        update_runnable(
            &mut *next_context_guard,
            percpu.cpu_id,
            schedule_time,
            next_is_current_sched,
        ),
        UpdateResult::CanSwitch
    ) {
        drop(prev_context_guard);
        drop(next_context_guard);
        return switch_inner(percpu, schedule_time, token);
    }

    //info!("DIRECT SWITCHING `{}` => `{}`", prev_context_guard.name, next_context_guard.name);
    //info!("DIRECT SWITCHING");

    let addr_space = next_context_guard
        .addr_space()
        .ok()
        .map(|addrsp| unsafe { AddrSpaceSwitchReadGuard::new(addrsp.inner.read(token.token())) });

    unsafe {
        switch_to(
            percpu,
            prev_context_guard,
            next_context_guard,
            addr_space,
            schedule_time,
            was_idle,
        );
    }

    SwitchResult::Switched
}

// SAFETY:
//
// - percpu must be the current hardware thread's
// - prev_context_guard must be a write guard of the current context
// - addr_space_guard must be a guard of the next context's addrsp
unsafe fn switch_to(
    percpu: &PercpuBlock,
    mut prev_context_guard: ArcRwLockWriteGuard<L4, Context>,
    mut next_context_guard: ArcRwLockWriteGuard<L4, Context>,
    addr_space_guard: Option<AddrSpaceSwitchReadGuard>,
    switch_time: u128,
    was_idle: bool,
) {
    // Update context states and prepare for the switch.
    let prev_context = &mut *prev_context_guard;
    let next_context = &mut *next_context_guard;

    // Set the previous context as "not running"
    prev_context.running = false;

    // Set the next context as "running"
    next_context.running = true;
    // Set the CPU ID for the next context
    next_context.cpu_id = Some(percpu.cpu_id);

    // Update times
    if !was_idle {
        prev_context.active_cpu_time += switch_time.saturating_sub(prev_context.switch_time);
    }
    next_context.switch_time = switch_time;
    if next_context.userspace {
        percpu.stats.set_state(cpu_stats::CpuState::User);
    } else {
        percpu.stats.set_state(cpu_stats::CpuState::Kernel);
    }
    unsafe {
        percpu
            .switch_internals
            .set_current_context(Arc::clone(ArcContextLockWriteGuard::rwlock(
                &next_context_guard,
            )));
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
    prev_context.inside_syscall = percpu.inside_syscall.replace(next_context.inside_syscall);

    #[cfg(feature = "profiling")]
    {
        percpu
            .switch_internals
            .current_dbg_id
            .store(next_context.debug_id, Ordering::Relaxed);
    }

    #[cfg(feature = "syscall_debug")]
    {
        let mut token = unsafe { CleanLockToken::new() }; // TODO
        let token = &mut token;
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
        percpu.new_addrsp_guard.set(addr_space_guard);
        arch::switch_to(prev_context, next_context);
    }
}

/// Holds per-CPU state necessary for context switching.
///
/// This struct contains information such as the idle context, current context, and PIT tick counts,
/// as well as fields required for managing ptrace sessions and signals.
pub struct ContextSwitchPercpu {
    switch_result: Cell<Option<SwitchResultInner>>,
    switch_time: Cell<u128>,
    schedule_time: Cell<u128>,
    pit_ticks: Cell<usize>,

    current_ctxt: RefCell<Option<Arc<ContextLock>>>,
    sched_ctxt: RefCell<Option<Arc<ContextLock>>>,

    // TODO: just access current_ctxt directly?
    #[cfg(feature = "profiling")]
    pub(crate) current_dbg_id: core::sync::atomic::AtomicU32,

    /// The idle process.
    idle_ctxt: RefCell<Option<Arc<ContextLock>>>,
    pub(crate) being_sigkilled: Cell<bool>,

    // wakeups
    pub(crate) ipi_context_wakeup_list: Mutex<L4, Vec<WeakContextRef>>,
    pub(crate) local_wakeup_list: RefCell<Vec<WeakContextRef>>,
    tmp_wakeups: RefCell<Vec<(Option<u128>, WeakContextRef)>>,
    tmp_timers: RefCell<Vec<(u128, WeakContextRef)>>,

    /// Holds the data necessary for work-stealing
    /// (key, weight, context_ref, guard, addr_space)
    tmp_steal: RefCell<
        Vec<(
            (u64, Reverse<u64>, u32), // key (vd, rem_slice, ctxt_id)
            u64,                      // weight
            WeakContextRef,
            ArcRwLockWriteGuard<L4, Context>,
            Option<AddrSpaceSwitchReadGuard>,
        )>,
    >,

    /// Run Queue
    pub(crate) run_queue: SpinMutex<RunContextData>,

    pub(crate) stealable: AtomicBool,
    pub(crate) queue_len: AtomicUsize,
    pub(crate) total_weight: AtomicU64,
    pub(crate) steal_counter: AtomicUsize,
}

impl ContextSwitchPercpu {
    pub const fn default() -> Self {
        Self {
            switch_result: Cell::new(None),
            schedule_time: Cell::new(0),
            switch_time: Cell::new(0),
            pit_ticks: Cell::new(0),
            current_ctxt: RefCell::new(None),
            sched_ctxt: RefCell::new(None),
            idle_ctxt: RefCell::new(None),
            being_sigkilled: Cell::new(false),
            ipi_context_wakeup_list: Mutex::new(Vec::new()),
            local_wakeup_list: RefCell::new(Vec::new()),
            tmp_wakeups: RefCell::new(Vec::new()),
            tmp_timers: RefCell::new(Vec::new()),
            tmp_steal: RefCell::new(Vec::new()),
            run_queue: SpinMutex::new(RunContextData::new()),
            stealable: AtomicBool::new(false),
            queue_len: AtomicUsize::new(0),
            total_weight: AtomicU64::new(0),
            steal_counter: AtomicUsize::new(0),

            #[cfg(feature = "profiling")]
            current_dbg_id: core::sync::atomic::AtomicU32::new(!0),
        }
    }

    /// Gets a reference to the raw current context slot.
    pub fn current_context_raw(&self) -> Ref<'_, Option<Arc<ContextLock>>> {
        self.current_ctxt.borrow()
    }

    /// Gets a reference to the current context, which will always be populated after the startup
    /// code (unless there are kernel bugs).
    pub fn current_context(&self) -> Ref<'_, Arc<ContextLock>> {
        Ref::map(self.current_ctxt.borrow(), |c| {
            c.as_ref().expect("no current context present")
        })
    }

    /// Gets a reference to the sched context, also always present after the startup code.
    pub fn sched_context(&self) -> Ref<'_, Arc<ContextLock>> {
        Ref::map(self.sched_ctxt.borrow(), |c| {
            c.as_ref().expect("no sched context present")
        })
    }

    /// Sets the current context.
    ///
    /// # Safety
    /// This function is unsafe as it modifies the context state directly.
    pub unsafe fn set_current_context(&self, new: Arc<ContextLock>) {
        *self.current_ctxt.borrow_mut() = Some(new);
    }

    pub unsafe fn set_sched_context(&self, new: Arc<ContextLock>) {
        *self.sched_ctxt.borrow_mut() = Some(new);
    }

    /// Sets the idle context to a new value.
    ///
    /// # Safety
    /// This function is unsafe as it modifies the idle context state directly.
    pub unsafe fn set_idle_context(&self, new: Arc<ContextLock>) {
        *self.idle_ctxt.borrow_mut() = Some(new);
    }

    /// Retrieves the current idle context.
    pub fn idle_context(&self) -> Ref<'_, Arc<ContextLock>> {
        Ref::map(self.idle_ctxt.borrow(), |opt| {
            opt.as_ref().expect("no idle context present")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Context, ContextLock, Status, WeakContextRef};
    use alloc::sync::Arc;
    use core::{cmp::Reverse, sync::atomic::Ordering};

    // FIXME: make this reusable to multiple tests
    #[cfg(test)]
    pub fn setup_cpus(count: u32) -> alloc::vec::Vec<&'static mut PercpuBlock> {
        let mut cpus = alloc::vec::Vec::new();

        for i in 0..count {
            let cpu = Box::leak(Box::new(PercpuBlock::init(LogicalCpuId::new(i))));

            unsafe {
                crate::percpu::init_tlb_shootdown(cpu.cpu_id, core::ptr::from_mut(cpu));

                ALL_PERCPU_BLOCKS[i as usize].store(cpu as *mut _, Ordering::Release);

                let idle_context = Arc::new(ContextLock::new(Context::new(None).unwrap()));
                cpu.switch_internals.set_idle_context(idle_context);
            }

            cpu.switch_internals
                .stealable
                .store(true, Ordering::Relaxed);

            if i > 0 {
                assert!(crate::publish_cpu(cpu.cpu_id));
            } else {
                PercpuBlock::set_mock_current(cpu as *const _);
            }

            cpus.push(cpu);
        }

        assert!(crate::cpu_count() == count);

        cpus
    }

    #[cfg(test)]
    pub fn new_context() -> Arc<ContextLock> {
        Arc::new(ContextLock::new(Context::new(None).unwrap()))
    }

    #[cfg(test)]
    pub fn setup_contexts(count: usize) -> alloc::vec::Vec<Arc<ContextLock>> {
        let mut tasks = alloc::vec::Vec::new();
        for _ in 0..count {
            let task = new_context();
            unsafe {
                task.write_arc().status = crate::context::Status::Runnable;
            }
            tasks.push(task);
        }
        tasks
    }

    #[test]
    fn test_work_stealing() {
        let mut cpus = setup_cpus(2);
        let cpu1 = cpus.pop().unwrap();
        let cpu0 = cpus.pop().unwrap();

        let tasks = setup_contexts(4);
        let prev_context_0 = new_context();
        // for simplicity this is used for current context and not used in any queue
        let mut prev_guard_0 = unsafe {
            cpu0.switch_internals
                .set_current_context(Arc::clone(&prev_context_0));
            cpu1.switch_internals
                .set_current_context(Arc::clone(&prev_context_0));
            prev_context_0.write_arc()
        };
        // force switch to other context
        prev_guard_0.status = Status::Blocked;

        fn push_queue(
            task: &Arc<ContextLock>,
            id: u32,
            vtime: u64,
            mut queue: &mut spin::mutex::SpinMutexGuard<'_, RunContextData>,
        ) {
            queue.queue.insert(
                (vtime, Reverse(vtime), id),
                (vtime, 1024, WeakContextRef(Arc::downgrade(task))),
            );
        }
        fn check_and_reset_steal(cpu0: &mut PercpuBlock) {
            assert_eq!(
                cpu0.switch_internals.steal_counter.load(Ordering::Relaxed),
                1
            );
            // need to be done to guarantee the cpu will do stealing
            cpu0.switch_internals
                .steal_counter
                .store(0, Ordering::Relaxed);
        }

        // q0 have empty queue
        {
            let mut q1 = cpu1.switch_internals.run_queue.lock();
            push_queue(&tasks[0], 0, 200, &mut q1);
            cpu1.switch_internals.queue_len.store(1, Ordering::Relaxed);
        }

        let chosen = select_next_context(cpu0, cpu0.cpu_id, 1000, 100, false, &mut prev_guard_0);

        // CPU 0 should be idling and NOT steal from CPU 1
        assert_eq!(cpu0.switch_internals.run_queue.lock().queue.len(), 0);
        assert_eq!(cpu1.switch_internals.run_queue.lock().queue.len(), 1);
        assert_eq!(cpu1.switch_internals.queue_len.load(Ordering::Relaxed), 1);

        assert!(chosen.is_some_and(|(g, _)| Arc::ptr_eq(
            &cpu0.switch_internals.idle_context(),
            ArcContextLockWriteGuard::rwlock(&g)
        )));
        check_and_reset_steal(cpu0);

        // second test ---

        {
            let mut q1 = cpu1.switch_internals.run_queue.lock();
            push_queue(&tasks[1], 1, 300, &mut q1);
            push_queue(&tasks[2], 2, 400, &mut q1);
            push_queue(&tasks[3], 3, 500, &mut q1);
            cpu1.switch_internals.queue_len.store(4, Ordering::Relaxed);
        }

        let chosen = select_next_context(cpu0, cpu0.cpu_id, 2000, 100, false, &mut prev_guard_0);

        // CPU 0 should steal 2 tasks, 1 is pushed to its own queue
        assert_eq!(cpu0.switch_internals.run_queue.lock().queue.len(), 1);
        assert_eq!(cpu0.switch_internals.queue_len.load(Ordering::Relaxed), 1);
        assert_eq!(cpu1.switch_internals.run_queue.lock().queue.len(), 2);
        assert_eq!(cpu1.switch_internals.queue_len.load(Ordering::Relaxed), 2);
        assert!(chosen
            .is_some_and(|(g, _)| Arc::ptr_eq(&tasks[0], ArcContextLockWriteGuard::rwlock(&g))));
        check_and_reset_steal(cpu0);

        // third test ---

        let chosen = select_next_context(cpu1, cpu1.cpu_id, 2000, 100, false, &mut prev_guard_0);

        // CPU 1 should not steal task yet, but it has something to do
        assert_eq!(cpu0.switch_internals.run_queue.lock().queue.len(), 1);
        assert_eq!(cpu0.switch_internals.queue_len.load(Ordering::Relaxed), 1);
        assert_eq!(cpu1.switch_internals.run_queue.lock().queue.len(), 2);
        assert_eq!(cpu1.switch_internals.queue_len.load(Ordering::Relaxed), 2);
        assert!(chosen
            .is_some_and(|(g, _)| Arc::ptr_eq(&tasks[1], ArcContextLockWriteGuard::rwlock(&g))));
        check_and_reset_steal(cpu1);

        // fourth test ---

        let last_task = {
            cpu1.switch_internals.queue_len.store(0, Ordering::Relaxed);
            let mut q1 = cpu1.switch_internals.run_queue.lock();
            // move the extra task to cpu0
            q1.queue.pop_last().unwrap()
        };
        {
            let mut q0 = cpu0.switch_internals.run_queue.lock();
            q0.queue.insert(last_task.0, last_task.1);
            cpu0.switch_internals.queue_len.store(2, Ordering::Relaxed);
        };
        {
            let mut guard = unsafe { tasks[1].write_arc() };
            // make sure this will be skipped
            guard.status = Status::Blocked;
        }

        let chosen = select_next_context(cpu1, cpu1.cpu_id, 2000, 100, false, &mut prev_guard_0);

        // CPU 1 should steal 1 task from CPU 0 used as the chosen one
        assert_eq!(cpu0.switch_internals.run_queue.lock().queue.len(), 1);
        assert_eq!(cpu0.switch_internals.queue_len.load(Ordering::Relaxed), 1);
        assert_eq!(cpu1.switch_internals.run_queue.lock().queue.len(), 0);
        assert_eq!(cpu1.switch_internals.queue_len.load(Ordering::Relaxed), 0);
        assert!(chosen
            .is_some_and(|(g, _)| Arc::ptr_eq(&tasks[2], ArcContextLockWriteGuard::rwlock(&g))));
        check_and_reset_steal(cpu1);
    }
}
