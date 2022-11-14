use crate::time;
use crate::context;
use crate::syscall::data::TimeSpec;
use crate::syscall::error::*;
use crate::syscall::flag::{CLOCK_REALTIME, CLOCK_MONOTONIC};

pub fn clock_gettime(clock: usize, time: &mut TimeSpec) -> Result<usize> {
    let arch_time = match clock {
        CLOCK_REALTIME => time::realtime(),
        CLOCK_MONOTONIC => time::monotonic(),
        _ => return Err(Error::new(EINVAL))
    };

    time.tv_sec = (arch_time / time::NANOS_PER_SEC) as i64;
    time.tv_nsec = (arch_time % time::NANOS_PER_SEC) as i32;
    Ok(0)
}

/// Nanosleep will sleep by switching the current context
pub fn nanosleep(req: &TimeSpec, rem_opt: Option<&mut TimeSpec>) -> Result<usize> {
    //start is a tuple of (seconds, nanoseconds)
    let start = time::monotonic();
    let end = start + (req.tv_sec as u128 * time::NANOS_PER_SEC) + (req.tv_nsec as u128);

    {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let mut context = context_lock.write();

        context.wake = Some(end);
        context.block("nanosleep");
    }

    //TODO: Find out wake reason
    loop {
        unsafe { context::switch(); }

        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let mut context = context_lock.write();
        if context.wake.is_some() {
            context.block("nanosleep spurious");
        } else {
            break;
        }
    }

    if let Some(rem) = rem_opt {
        let current = time::monotonic();

        if current < end {
            let diff = end - current;
            rem.tv_sec = (diff / time::NANOS_PER_SEC) as i64;
            rem.tv_nsec = (diff % time::NANOS_PER_SEC) as i32;
        } else {
            rem.tv_sec = 0;
            rem.tv_nsec = 0;
        }
    }

    Ok(0)
}

pub fn sched_yield() -> Result<usize> {
    unsafe { context::switch(); }
    Ok(0)
}
