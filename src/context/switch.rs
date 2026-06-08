//! This module provides a context-switching mechanism that utilizes a simple round-robin scheduler.
//! The scheduler iterates over available contexts, selecting the next context to run, while
//! handling process states and synchronization.

use crate::{
    context::{
        self, arch, idle_contexts, idle_contexts_try, memory::AddrSpaceSwitchReadGuard,
        run_contexts, ArcContextLockWriteGuard, Context, ContextLock, WeakContextRef,
    },
    cpu_set::LogicalCpuId,
    cpu_stats::{self, CpuState},
    percpu::PercpuBlock,
    sync::{ArcRwLockWriteGuard, CleanLockToken, L4},
};
use alloc::sync::Arc;
use core::{
    cell::{Cell, RefCell},
    hint, matches, mem,
    option::Option::{None, Some},
    sync::atomic::Ordering,
    u64,
};
use smallvec::SmallVec;
use syscall::PtraceFlags;

enum UpdateResult {
    CanSwitch,
    Skip,
    Blocked,
}

// A simple geometric series where value[i] ~= value[i + 1] * 1.25
const SCHED_PRIO_TO_WEIGHT: [usize; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

const SCALE: u128 = 1 << 40;
const TICK_INTERVAL: u64 = 3; // Approx 6.75 ms
const BASE_SLICE_TICKS: u64 = TICK_INTERVAL * 3; // Approx 20.25 ms
const NANOS_PER_TICK: u128 = 2_250_000; // 2.25 ms

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
    let wakeups = wakeup_contexts(token, switch_time);
    let wakeups_len = wakeups.len();

    if wakeups_len > 0 {
        let mut run_contexts = run_contexts(token.token());
        for context_ref in wakeups {
            run_contexts.queue.push_back(context_ref);
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

fn wakeup_contexts(
    token: &mut CleanLockToken,
    switch_time: u128,
) -> SmallVec<[WeakContextRef; 16]> {
    // TODO: Optimise this somehow. Perhaps using a separate timer queue?
    let mut wakeups = SmallVec::new();
    let current_context = context::current();
    let Some(idle_contexts) = idle_contexts_try(token.downgrade()) else {
        // other cpus may spawning or killing contexts so let's skip wakeups to avoid contention
        return wakeups;
    };
    let (mut idle_contexts, mut token) = idle_contexts.into_split();
    let len = idle_contexts.len();
    for _ in 0..len {
        let Some(context_ref) = idle_contexts.pop() else {
            break;
        };
        let Some(context) = context_ref.upgrade() else {
            continue;
        };
        if Arc::ptr_eq(&context, &current_context) {
            idle_contexts.push(context_ref);
            continue;
        }
        let Some(guard) = context.try_read(token.token()) else {
            idle_contexts.push(context_ref);
            continue;
        };
        if guard.status.is_soft_blocked() {
            if let Some(wake) = guard.wake {
                if switch_time >= wake {
                    drop(guard);
                    wakeups.push(context_ref);
                    continue;
                } else {
                    break;
                }
            }
        } else if guard.status.is_dead() {
            // TODO: who hold this dead context?
            continue;
        }

        if guard.status.is_runnable() && !guard.running {
            drop(guard);
            wakeups.push(context_ref);
            continue;
        }

        drop(guard);
        idle_contexts.push(context_ref);
    }
    wakeups
}

/// This is the scheduler function which currently utilises Deficit Weighted Round Robin Scheduler
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

    let elapsed_ticks = elapsed_time as u128 * SCALE / NANOS_PER_TICK;

    if prev_runnable {
        let weight = SCHED_PRIO_TO_WEIGHT[prev_context_guard.prio] as u64;
        prev_context_guard.rem_slice = prev_context_guard
            .rem_slice
            .saturating_sub((elapsed_ticks / SCALE) as u64);
        let scaled_task = elapsed_ticks / weight as u128;
        prev_context_guard.vtime += scaled_task as u64;

        if prev_context_guard.vtime < contexts_data.v {
            prev_context_guard.vtime = contexts_data.v;
        }

        if prev_context_guard.rem_slice == 0 {
            prev_context_guard.rem_slice = BASE_SLICE_TICKS;
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
    }

    let mut min_active_vtime: u64 = if prev_runnable {
        prev_context_guard.vtime
    } else {
        u64::MAX
    };

    let mut eligible_best = None;
    let mut eligible_min_vd = u64::MAX;
    let mut eligible_best_rem = u64::MAX;
    let mut eligible_found = false;

    let mut ineligible_best = None;
    let mut ineligible_min_vtime = u64::MAX;
    let mut ineligible_min_vd = u64::MAX;
    let mut ineligible_best_rem = u64::MAX;

    if prev_runnable {
        if prev_context_guard.vtime <= contexts_data.v {
            eligible_found = true;
            eligible_min_vd = prev_context_guard.vd;
            eligible_best_rem = prev_context_guard.rem_slice;
        } else {
            ineligible_min_vtime = prev_context_guard.vtime;
            ineligible_min_vd = prev_context_guard.vd;
            ineligible_best_rem = prev_context_guard.rem_slice;
        }
    }

    let mut skipped_dead = 0;
    let mut i = 0;

    while i < contexts_data.queue.len() {
        let context_ref = &contexts_data.queue[i];

        let Some(context_lock) = context_ref.upgrade() else {
            skipped_dead += 1;
            contexts_data.queue.remove(i);
            continue;
        };

        if Arc::ptr_eq(&context_lock, &idle_context)
            || Arc::ptr_eq(&context_lock, &prev_context_lock)
        {
            i += 1;
            continue;
        }

        let Some(mut guard) = (unsafe { context_lock.try_write_arc() }) else {
            i += 1;
            continue;
        };

        let sw = unsafe { update_runnable(&mut guard, cpu_id, switch_time) };

        if matches!(sw, UpdateResult::Blocked) {
            if guard.is_active {
                guard.is_active = false;
                let weight = SCHED_PRIO_TO_WEIGHT[guard.prio] as u64;
                contexts_data.total_weight = contexts_data.total_weight.saturating_sub(weight);
            }
            guard.rem_slice = 0;
            drop(guard);
            let removed_ref = contexts_data.queue.remove(i).unwrap();
            idle_contexts(token.token()).push(removed_ref);
            continue;
        }

        if !matches!(sw, UpdateResult::CanSwitch) {
            i += 1;
            continue;
        }

        let mut best_addr_space = None;
        if let Some(addr_space) = &guard.addr_space {
            let mut t = unsafe { CleanLockToken::new() };
            if let Some(addr) = addr_space.inner.try_read(t.token()) {
                best_addr_space = Some(AddrSpaceSwitchReadGuard::new(addr));
            } else {
                i += 1;
                continue;
            }
        }

        let weight = SCHED_PRIO_TO_WEIGHT[guard.prio] as u64;

        if !guard.is_active {
            guard.is_active = true;
            contexts_data.total_weight += weight;
        }

        if guard.vtime < min_active_vtime {
            min_active_vtime = guard.vtime;
        }

        let vd = guard.vd;
        let rem = guard.rem_slice;

        if guard.vtime <= contexts_data.v {
            // Eligible
            if !eligible_found {
                eligible_found = true;
                eligible_min_vd = u64::MAX;
                eligible_best_rem = u64::MAX;
                eligible_best = None;
            }
            if vd < eligible_min_vd || (vd == eligible_min_vd && rem < eligible_best_rem) {
                eligible_min_vd = vd;
                eligible_best_rem = rem;
                eligible_best = Some((i, guard, best_addr_space));
            }
        } else {
            // Ineligible
            if guard.vtime < ineligible_min_vtime
                || (guard.vtime == ineligible_min_vtime
                    && (vd < ineligible_min_vd
                        || (vd == ineligible_min_vd && rem < ineligible_best_rem)))
            {
                ineligible_min_vtime = guard.vtime;
                ineligible_min_vd = vd;
                ineligible_best_rem = rem;
                ineligible_best = Some((i, guard, best_addr_space));
            }
        }

        i += 1;
    }

    if !eligible_found && min_active_vtime != u64::MAX {
        contexts_data.v = min_active_vtime;

        let prev_is_earliest = prev_runnable && prev_context_guard.vtime <= ineligible_min_vtime;

        if prev_is_earliest {
            eligible_found = true;
            eligible_min_vd = prev_context_guard.vd;
            eligible_best_rem = prev_context_guard.rem_slice;
            eligible_best = None;
        } else if ineligible_best.is_some() {
            let prev_has_slice = prev_runnable && prev_context_guard.rem_slice > 0;

            if prev_has_slice && prev_context_guard.vd <= ineligible_min_vd {
                eligible_found = true;
                eligible_best = None;
            } else {
                eligible_found = true;
                eligible_min_vd = ineligible_min_vd;
                eligible_best_rem = ineligible_best_rem;
                eligible_best = ineligible_best.take();
            }
        }
    }

    let mut final_winner = None;

    if let Some((idx, chosen_guard, addr_space)) = eligible_best {
        contexts_data.queue.remove(idx).unwrap();
        final_winner = Some((chosen_guard, addr_space));
    }

    if skipped_dead > 10 {
        contexts_data.queue.retain(|x| x.upgrade().is_some());
    }

    if final_winner.is_some() || prev_runnable {
        if contexts_data.total_weight > 0 {
            let v_advance = elapsed_ticks as u128 / contexts_data.total_weight as u128;
            contexts_data.v += v_advance as u64;
        }

        if let Some((chosen_guard, addr_space)) = final_winner {
            let weight = SCHED_PRIO_TO_WEIGHT[chosen_guard.prio] as u64;

            /*
            chosen_guard.rem_slice = chosen_guard.rem_slice.saturating_sub(TICK_INTERVAL);
            let scaled_task = elapsed / weight as u128;
            chosen_guard.vtime += scaled_task as u64;
            */

            if prev_runnable {
                contexts_data
                    .queue
                    .push_back(WeakContextRef(Arc::downgrade(&prev_context_lock)));
            } else if !is_idle {
                idle_contexts(token.token())
                    .push(WeakContextRef(Arc::downgrade(&prev_context_lock)));
            }

            return Some((chosen_guard, addr_space));
        } else {
            return None;
        }
    } else {
        if !is_idle {
            idle_contexts(token.token())
                .push(WeakContextRef(Arc::downgrade(&prev_context_lock)));
        }

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
