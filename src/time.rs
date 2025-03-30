use spin::Mutex;

use crate::syscall::error::{Error, Result, EINVAL};

pub const NANOS_PER_SEC: u128 = 1_000_000_000;

// TODO: seqlock?
/// Kernel start time, measured in nanoseconds since Unix epoch
pub static START: Mutex<u128> = Mutex::new(0);
/// Kernel up time, measured in nanoseconds since `START_TIME`
pub static OFFSET: Mutex<u128> = Mutex::new(0);

pub fn monotonic() -> u128 {
    crate::arch::time::monotonic_absolute()
}

pub fn realtime() -> u128 {
    *START.lock() + monotonic()
}

pub fn sys_update_time_offset(buf: &[u8]) -> Result<usize> {
    let start = <[u8; 16]>::try_from(buf).map_err(|_| Error::new(EINVAL))?;
    *START.lock() = u128::from_ne_bytes(start);
    Ok(16)
}
