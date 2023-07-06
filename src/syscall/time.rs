use crate::time;
use crate::context;
use crate::syscall::data::TimeSpec;
use crate::syscall::error::*;
use crate::syscall::flag::{CLOCK_REALTIME, CLOCK_MONOTONIC};

use super::usercopy::{UserSliceRo, UserSliceWo};

pub fn clock_gettime(clock: usize, buf: UserSliceWo) -> Result<()> {
    let arch_time = match clock {
        CLOCK_REALTIME => time::realtime(),
        CLOCK_MONOTONIC => time::monotonic(),
        _ => return Err(Error::new(EINVAL))
    };

    buf.copy_exactly(&TimeSpec {
        tv_sec: (arch_time / time::NANOS_PER_SEC) as i64,
        tv_nsec: (arch_time % time::NANOS_PER_SEC) as i32,
    })
}

/// Nanosleep will sleep by switching the current context
pub fn nanosleep(req_buf: UserSliceRo, rem_buf_opt: Option<UserSliceWo>) -> Result<()> {
    let req = unsafe { req_buf.read_exact::<TimeSpec>()? };

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

    if let Some(rem_buf) = rem_buf_opt {
        let current = time::monotonic();

        rem_buf.copy_exactly(&if current < end {
            let diff = end - current;
            TimeSpec {
                tv_sec: (diff / time::NANOS_PER_SEC) as i64,
                tv_nsec: (diff % time::NANOS_PER_SEC) as i32,
            }
        } else {
            TimeSpec {
                tv_sec: 0,
                tv_nsec: 0,
            }
        })?;
    }

    Ok(())
}

pub fn sched_yield() -> Result<()> {
    unsafe { context::switch(); }
    Ok(())
}
