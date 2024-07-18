use crate::{
    context,
    syscall::{
        data::TimeSpec,
        error::*,
        flag::{CLOCK_MONOTONIC, CLOCK_REALTIME},
    },
    time,
};

use super::usercopy::{UserSliceRo, UserSliceWo};

pub fn clock_gettime(clock: usize, buf: UserSliceWo) -> Result<()> {
    let arch_time = match clock {
        CLOCK_REALTIME => time::realtime(),
        CLOCK_MONOTONIC => time::monotonic(),
        _ => return Err(Error::new(EINVAL)),
    };

    buf.copy_exactly(&TimeSpec {
        tv_sec: (arch_time / time::NANOS_PER_SEC) as i64,
        tv_nsec: (arch_time % time::NANOS_PER_SEC) as i32,
    })
}

/// Nanosleep will sleep by switching the current context
pub fn nanosleep(req_buf: UserSliceRo, rem_buf_opt: Option<UserSliceWo>) -> Result<()> {
    let req = unsafe { req_buf.read_exact::<TimeSpec>()? };

    let start = time::monotonic();
    let end = start + (req.tv_sec as u128 * time::NANOS_PER_SEC) + (req.tv_nsec as u128);

    let current_context = context::current();
    {
        let mut context = current_context.write();

        if let Some((tctl, pctl, _)) = context.sigcontrol() {
            if tctl.currently_pending_unblocked(pctl) != 0 {
                return Err(Error::new(EINTR));
            }
        }

        context.wake = Some(end);
        context.block("nanosleep");
    }

    // TODO: The previous wakeup reason was most likely signals, but is there any other possible
    // reason?
    context::switch();

    if current_context.write().wake.take().is_some() {
        return Err(Error::new(EINTR));
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
    context::switch();
    // TODO: Do this check in userspace
    context::signal::signal_handler();
    Ok(())
}
