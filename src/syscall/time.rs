use crate::{
    context,
    sync::CleanLockToken,
    syscall::{
        data::TimeSpec,
        error::*,
        flag::{CLOCK_MONOTONIC, CLOCK_REALTIME},
    },
    time,
};

use super::usercopy::{UserSliceRo, UserSliceWo};

pub fn clock_gettime(clock: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<()> {
    let arch_time = match clock {
        CLOCK_REALTIME => time::realtime(token),
        CLOCK_MONOTONIC => time::monotonic(token),
        _ => return Err(Error::new(EINVAL)),
    };

    buf.copy_exactly(&TimeSpec::from_nanos(arch_time))
}

/// Nanosleep will sleep by switching the current context
pub fn nanosleep(
    req_buf: UserSliceRo,
    rem_buf_opt: Option<UserSliceWo>,
    token: &mut CleanLockToken,
) -> Result<()> {
    let req = unsafe { req_buf.read_exact::<TimeSpec>()? };

    if req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= time::NANOS_PER_SEC as i32 {
        return Err(Error::new(EINVAL));
    }

    let start = time::monotonic(token);
    let end = start + req.to_nanos();

    let current_context = context::current();
    {
        let context = current_context.upgradeable_read(token.token());

        if let Some((tctl, pctl, _)) = context.sigcontrol()
            && tctl.currently_pending_unblocked(pctl) != 0
        {
            return Err(Error::new(EINTR));
        }
        let mut context = context.upgrade();
        context.wake = Some(end);
        context.block("nanosleep");
    }

    // TODO: The previous wakeup reason was most likely signals, but is there any other possible
    // reason?
    context::switch(token);

    let was_interrupted = current_context.write(token.token()).wake.take().is_some();

    if let Some(rem_buf) = rem_buf_opt {
        let current = time::monotonic(token);

        rem_buf.copy_exactly(&if current < end {
            let diff = end - current;
            TimeSpec::from_nanos(diff)
        } else {
            TimeSpec::default()
        })?;
    }

    if was_interrupted {
        Err(Error::new(EINTR))
    } else {
        Ok(())
    }
}

pub fn sched_yield(token: &mut CleanLockToken) -> Result<()> {
    context::switch(token);
    // TODO: Do this check in userspace
    context::signal::signal_handler(token);
    Ok(())
}
