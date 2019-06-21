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

    time.tv_sec = arch_time.0 as i64;
    time.tv_nsec = arch_time.1 as i32;
    Ok(0)
}

/// Nanosleep will sleep by switching the current context
pub fn nanosleep(req: &TimeSpec, rem_opt: Option<&mut TimeSpec>) -> Result<usize> {
    //start is a tuple of (seconds, nanoseconds)
    let start = time::monotonic();
    let sum = start.1 + req.tv_nsec as u64;
    let end = (start.0 + req.tv_sec as u64 + sum / 1_000_000_000, sum % 1_000_000_000);

    {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let mut context = context_lock.write();

        context.wake = Some(end);
        context.block();
    }

    unsafe { context::switch(); }

    if let Some(rem) = rem_opt {
        //TODO let current = time::monotonic();
        rem.tv_sec = 0;
        rem.tv_nsec = 0;
    }

    Ok(0)
}

pub fn sched_yield() -> Result<usize> {
    unsafe { context::switch(); }
    Ok(0)
}
