use alloc::collections::VecDeque;
use spin::{Once, Mutex, MutexGuard};

use crate::event;
use crate::scheme::SchemeId;
use crate::syscall::data::TimeSpec;
use crate::syscall::flag::{CLOCK_MONOTONIC, CLOCK_REALTIME, EVENT_READ};
use crate::time;

#[derive(Debug)]
struct Timeout {
    pub scheme_id: SchemeId,
    pub event_id: usize,
    pub clock: usize,
    pub time: (u64, u64),
}

type Registry = VecDeque<Timeout>;

static REGISTRY: Once<Mutex<Registry>> = Once::new();

/// Initialize registry, called if needed
fn init_registry() -> Mutex<Registry> {
    Mutex::new(Registry::new())
}

/// Get the global timeouts list
fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY.call_once(init_registry).lock()
}

pub fn register(scheme_id: SchemeId, event_id: usize, clock: usize, time: TimeSpec) {
    let mut registry = registry();
    registry.push_back(Timeout {
        scheme_id,
        event_id,
        clock,
        time: (time.tv_sec as u64, time.tv_nsec as u64)
    });
}

pub fn trigger() {
    let mut registry = registry();

    let mono = time::monotonic();
    let real = time::realtime();

    let mut i = 0;
    while i < registry.len() {
        let trigger = match registry[i].clock {
            CLOCK_MONOTONIC => {
                let time = registry[i].time;
                mono.0 > time.0 || (mono.0 == time.0 && mono.1 >= time.1)
            },
            CLOCK_REALTIME => {
                let time = registry[i].time;
                real.0 > time.0 || (real.0 == time.0 && real.1 >= time.1)
            },
            clock => {
                println!("timeout::trigger: unknown clock {}", clock);
                true
            }
        };

        if trigger {
            let timeout = registry.remove(i).unwrap();
            event::trigger(timeout.scheme_id, timeout.event_id, EVENT_READ);
        } else {
            i += 1;
        }
    }
}
