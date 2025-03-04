#![allow(dead_code, unused_imports)]

use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use alloc::{string::String, sync::Arc};
use spin::{Lazy, Mutex, RwLock};
use spinning_top::{lock_api::ArcRwLockWriteGuard, RawRwSpinlock, RwSpinlock};

use crate::{
    context::{
        arch,
        context::HardBlockedReason,
        contexts,
        scheduler::{
            context_switch::UpdateResult, support::update_runnable, SwitchResult, QUANTUM_SIZE,
        },
        Context, ContextRef, Status,
    },
    cpu_count,
    cpu_set::{LogicalCpuId, LogicalCpuSet},
    interrupt,
    percpu::PercpuBlock,
    time,
};

use super::{
    request_node::RequestTimings, request_tree::RequestTree, virtual_time::VirtualTime,
    NodeHandleRef,
};

static REQUEST_TREE: Lazy<Arc<RwLock<RequestTree<ContextRef>>>> =
    Lazy::new(|| Arc::new(RwLock::new(RequestTree::new())));
static VIRTUAL_TIME: RwLock<VirtualTime> = RwLock::new(VirtualTime::new(0.0));
static TOTAL_WEIGHTS: AtomicI64 = AtomicI64::new(1);

/// Get the next context to run on the given CPU.
///
/// # Parameters
/// * `percpu` - Information on the current CPU,
/// * `cpu_id` - The id of the current CPU.
pub fn get_next_context(
    percpu: &PercpuBlock,
    cpu_id: LogicalCpuId,
) -> Option<(
    ArcRwLockWriteGuard<RawRwSpinlock, Context>,
    ArcRwLockWriteGuard<RawRwSpinlock, Context>,
)> {
    wake_sleeping_contexts();

    let mut contexts_string = alloc::string::String::new();
    for ctx in contexts()
        .iter()
        .filter_map(|ctx| ctx.upgrade())
        .filter(|ctx| matches!(ctx.read().status, Status::Runnable))
        .map(|ctx| ctx.read().pid.get())
    {
        contexts_string = format!("{contexts_string}, {ctx}");
    }
    log::debug!(
        "looking for next context, tree has size {}, (min_eligible = {:?}, current time: {}, total_weights = {}, runnable = {}, contexts: {contexts_string})",
        REQUEST_TREE.read().nb_nodes(),
        REQUEST_TREE.read().min_eligible(),
        *VIRTUAL_TIME.read(),
        TOTAL_WEIGHTS.load(Ordering::Acquire),
        contexts().iter().filter_map(|ctx| ctx.upgrade()).filter(|ctx| matches!(ctx.read().status,Status::Runnable)).count(),
    );

    let idle_context = percpu.switch_internals.idle_context();
    let prev_context_lock = crate::context::current();
    let used = percpu.switch_internals.pit_ticks.get();
    let mut tree = REQUEST_TREE.write();

    if !Arc::ptr_eq(&prev_context_lock, &idle_context) {
        log::debug!(
            "prev context wasn’t the idle one ({:?}), adding it back to the tree",
            prev_context_lock.read().pid
        );
        update_prev_context(&prev_context_lock, used);
        issue_new_request(&mut tree, &prev_context_lock, used);
    } else {
        forward_time();
    }

    let prev_context_guard = prev_context_lock.write_arc();
    let next_context_lock = match tree
        .get_first_eligible(cpu_id, *VIRTUAL_TIME.read())
        .inspect(|_context| log::debug!("found context"))
        .and_then(|context| context.upgrade())
    {
        Some(ctx) if !Arc::ptr_eq(&prev_context_lock, &ctx) => ctx,
        Some(_) => {
            log::debug!("next context found, but same as previous: going idle");
            return Some((prev_context_guard, idle_context.write_arc()));
        }
        None if !Arc::ptr_eq(&prev_context_lock, &idle_context) => {
            log::debug!("no context found, switching to idle context");
            return Some((prev_context_guard, idle_context.write_arc()));
        }
        None => {
            log::debug!(
                "no context found, was already idle, nothing to do. Time is {}, tree has {} elements",
                *VIRTUAL_TIME.read(),
                tree.nb_nodes()
            );
            return None;
        }
    };

    let mut next_context_guard = next_context_lock.write_arc();
    tree.remove(
        ContextRef(Arc::clone(&next_context_lock)),
        next_context_guard.eevdf_data.timings,
    );

    if next_context_guard.status.is_runnable()
        || matches!(
            next_context_guard.status,
            Status::HardBlocked {
                reason: HardBlockedReason::NotYetStarted,
            },
        )
    {
        next_context_guard.eevdf_data.is_running = true;
        Some((prev_context_guard, next_context_guard))
    } else {
        panic!("...... next context is NOT runnable! Why is it still in the tree then???\n{next_context_guard:#?}\n{tree:?}");
        // None
    }
}

/// Subscribe a context to the scheduler
///
/// This functions takes both a mutable reference to the context (which can come from a write lock)
/// and a [`ContextRef`]. The latter is only used to store the address of the concept, never to access
/// its data so there can be no deadlock happening.
///
/// # Parameters
/// * `context` - A write lock on the context,
/// * `context_ref` - The context’s reference.
pub fn context_join(context: &mut Context, context_ref: ContextRef) {
    if !context.status.is_runnable()
        && !matches!(
            context.status,
            Status::HardBlocked {
                reason: HardBlockedReason::NotYetStarted,
            },
        )
    {
        log::warn!("Non-runnable context tried to join:\n{context:#?}");
    }
    if context.eevdf_data.has_joined {
        log::debug!("Context {:?} has already joined", context.pid);
        return;
    }
    let mut tree = REQUEST_TREE.write();
    context.eevdf_data.has_joined = true;

    log::debug!(
        "Joining with PID {:?}, (lag = {}, status: {:?})",
        context.pid,
        context.eevdf_data.lag,
        context.status,
    );
    let mut virtual_time = VIRTUAL_TIME.write();
    let weight = context.eevdf_data.weight;
    let total_weight = weight + TOTAL_WEIGHTS.fetch_add(weight, Ordering::AcqRel);
    *virtual_time -= VirtualTime::new(context.eevdf_data.lag as f64 / total_weight as f64);

    context.eevdf_data.timings.eligible = *virtual_time;
    context.eevdf_data.timings.deadline =
        context.eevdf_data.timings.eligible + VirtualTime::new(QUANTUM_SIZE as f64 / weight as f64);
    tree.insert(context_ref, context.eevdf_data.timings);
}

/// Removes a context from the scheduler
///
/// This functions takes both a mutable reference to the context (which can come from a write lock)
/// and a [`ContextRef`]. The latter is only used to store the address of the concept, never to access
/// its data so there can be no deadlock happening.
///
/// # Parameters
/// * `context` - A write lock on the context,
/// * `context_ref` - The context’s reference.
pub fn context_leave(context: &mut Context, context_ref: ContextRef) {
    log::debug!(
        "leaving with PID {:?}, (lag = {}, status = {:?})",
        context.pid,
        context.eevdf_data.lag,
        context.status
    );

    if !context.eevdf_data.has_joined {
        log::debug!(".. the context has already left, nothing to do");
        return;
    }
    let mut tree = REQUEST_TREE.write();
    context.eevdf_data.has_joined = false;

    let new_total = TOTAL_WEIGHTS.fetch_sub(context.eevdf_data.weight, Ordering::AcqRel)
        - context.eevdf_data.weight;
    let lag = context.eevdf_data.lag as f64;
    *VIRTUAL_TIME.write() += VirtualTime::new(lag / new_total as f64);

    if context.eevdf_data.is_running {
        log::debug!(".. context {:?} is running, nothing to remove", context.pid);
        return;
    }

    log::debug!(".. removing the context’s request");
    tree.remove(context_ref.clone(), context.eevdf_data.timings);
}

fn get_context_to_wake() -> alloc::vec::Vec<ContextRef> {
    let now = time::monotonic();
    contexts()
        .iter()
        .filter(|ctx| {
            ctx.upgrade()
                .map_or(false, |ctx| ctx.read().wake.is_some_and(|wake| wake < now))
        })
        .cloned()
        .collect()
}

fn wake_sleeping_contexts() {
    for context_ref in get_context_to_wake() {
        let Some(lock) = context_ref.upgrade() else {
            continue;
        };
        let mut context = lock.write();
        context.wake = None;
        context.status = Status::Runnable;
        context.status_reason = "";
        context_join(&mut context, context_ref.clone());
    }
}

fn forward_time() {
    let delta_vt = VirtualTime::new(1.0 / TOTAL_WEIGHTS.load(Ordering::Acquire) as f64);
    *VIRTUAL_TIME.write() += delta_vt;
}

fn update_prev_context(context_lock: &Arc<RwSpinlock<Context>>, used: usize) {
    let lag = QUANTUM_SIZE.saturating_sub(used);

    let mut context = context_lock.write();
    context.eevdf_data.used += used as u64;
    context.eevdf_data.lag += lag;
    context.eevdf_data.is_running = false;

    let delta_vt = VirtualTime::new(
        used as f64 * context.eevdf_data.weight as f64
            / TOTAL_WEIGHTS.load(Ordering::Acquire) as f64,
    );
    *VIRTUAL_TIME.write() += delta_vt;
}

fn issue_new_request(
    tree: &mut RequestTree<ContextRef>,
    context_lock: &Arc<RwSpinlock<Context>>,
    used: usize,
) {
    let mut context = context_lock.write();
    if !context.eevdf_data.has_joined {
        // Context was running, but removed itself from the tree
        // so we don’t want to add it back here, it’ll do so explicitely.
        return;
    }

    let weight = context.eevdf_data.weight as f64;
    let vt_used = VirtualTime::new(used as f64 / weight);
    let vt_alloc = VirtualTime::new(QUANTUM_SIZE as f64 / weight);
    context.eevdf_data.timings.eligible += vt_used;
    context.eevdf_data.timings.deadline = context.eevdf_data.timings.eligible + vt_alloc;

    tree.insert(
        ContextRef(Arc::clone(context_lock)),
        context.eevdf_data.timings,
    );
}
