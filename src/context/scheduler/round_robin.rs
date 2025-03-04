///! This module provides a context-switching mechanism that utilizes a simple round-robin scheduler.
///! The scheduler iterates over available contexts, selecting the next context to run, while
///! handling process states and synchronization.
use core::ops::Bound;

use alloc::sync::Arc;
use spinning_top::{lock_api::ArcRwLockWriteGuard, RawRwSpinlock};

use crate::{
    context::{contexts, Context},
    cpu_set::LogicalCpuId,
    percpu::PercpuBlock,
};

#[cfg(feature = "sys_stat")]
use crate::cpu_stats;

use super::{super::ContextRef, context_switch::UpdateResult, support::update_runnable};

pub fn get_next_context(
    percpu: &PercpuBlock,
    cpu_id: LogicalCpuId,
) -> Option<(
    ArcRwLockWriteGuard<RawRwSpinlock, Context>,
    ArcRwLockWriteGuard<RawRwSpinlock, Context>,
)> {
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
            return Some((prev_context_guard, next_context_guard));
        }
    }

    None
}
