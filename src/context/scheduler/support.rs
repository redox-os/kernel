use core::sync::atomic::Ordering;

use crate::{
    context::{arch, Context},
    cpu_set::LogicalCpuId,
    percpu::PercpuBlock,
    time,
};

use super::{context_switch::UpdateResult, QUANTUM_SIZE};

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
    if new_ticks >= QUANTUM_SIZE {
        super::switch();
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
pub unsafe fn update_runnable(context: &mut Context, cpu_id: LogicalCpuId) -> UpdateResult {
    if !cfg!(feature = "scheduler_eevdf") {
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
    }

    // If context is soft-blocked and has a wake-up time, check if it should wake up.
    if context.status.is_soft_blocked() {
        if let Some(wake) = context.wake {
            let current = time::monotonic();
            if current >= wake {
                if context.pid.get() == 18 {
                    log::debug!("... waking {:?}", context.pid);
                }
                log::debug!("waking up process {:?}", context.pid);
                context.wake = None;
                context.unblock_no_ipi();
            }
        }
    }

    // If the context is runnable, indicate it can be switched to.
    log::debug!("Context {:?} status is {:?}", context.pid, context.status);
    if context.status.is_runnable() {
        UpdateResult::CanSwitch
    } else {
        UpdateResult::Skip
    }
}
