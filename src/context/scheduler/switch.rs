use core::{mem, sync::atomic::Ordering};

use alloc::sync::Arc;
use spinning_top::guard::ArcRwSpinlockWriteGuard;
use syscall::PtraceFlags;

use crate::{
    context::{arch, Context},
    interrupt,
    percpu::PercpuBlock,
    ptrace,
};

use super::{context_switch::SwitchResultInner, get_next_context, SwitchResult};

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
    log::trace!("---------- switching context for {:?}", crate::cpu_id());
    #[cfg(feature = "sys_stat")]
    {
        cpu_stats::add_context_switch();
        percpu
            .stats
            .add_time(percpu.switch_internals.pit_ticks.get());
    }

    log::trace!(
        "---------- pausing interrupts and stuff for {:?}",
        crate::cpu_id()
    );

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
    log::trace!("---------- getting next context on {:?}", cpu_id);
    let switch_context_opt = get_next_context(&percpu, cpu_id);
    log::trace!("---------- got next context (or not)");

    //set PIT Interrupt counter to 0, giving each process same amount of PIT ticks
    percpu.switch_internals.pit_ticks.set(0);

    // Switch process states, TSS stack pointer, and store new context ID
    if let Some((mut prev_context_guard, mut next_context_guard)) = switch_context_opt {
        // Update context states and prepare for the switch.
        let prev_context = &mut *prev_context_guard;
        let next_context = &mut *next_context_guard;
        log::debug!(
            "got next context on {:?}: switching to context with PID {:?} (status: {:?})",
            cpu_id,
            next_context.pid,
            next_context.status
        );

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
        #[cfg(feature = "sys_stat")]
        {
            if next_context.userspace {
                percpu.stats.set_state(cpu_stats::CpuState::User);
            } else {
                percpu.stats.set_state(cpu_stats::CpuState::Kernel);
            }
        }

        SwitchResult::Switched
    } else {
        log::debug!("didn’t get anything to switch to…");
        // No target was found, unset global lock and return
        arch::CONTEXT_SWITCH_LOCK.store(false, Ordering::SeqCst);

        #[cfg(feature = "sys_stat")]
        {
            percpu.stats.set_state(cpu_stats::CpuState::Idle);
        }

        SwitchResult::AllContextsIdle
    }
}
