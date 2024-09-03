use spin::Mutex;

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
