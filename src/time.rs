use spin::Mutex;

pub const NANOS_PER_SEC: u128 = 1_000_000_000;

/// Kernel start time, measured in (seconds, nanoseconds) since Unix epoch
pub static START: Mutex<u128> = Mutex::new(0);
/// Kernel up time, measured in (seconds, nanoseconds) since `START_TIME`
pub static OFFSET: Mutex<u128> = Mutex::new(0);

pub fn monotonic() -> u128 {
    *OFFSET.lock() + crate::arch::time::counter()
}

pub fn realtime() -> u128 {
    *START.lock() + monotonic()
}
