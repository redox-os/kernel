use alloc::collections::VecDeque;
use core::fmt;
use spin::{Mutex, MutexGuard};

use crate::devices::graphical_debug::{DebugDisplay, DEBUG_DISPLAY};

pub static LOG: Mutex<Option<Log>> = Mutex::new(None);

pub fn init() {
    *LOG.lock() = Some(Log::new(1024 * 1024));
}

pub struct Log {
    data: VecDeque<u8>,
    size: usize,
}

impl Log {
    pub fn new(size: usize) -> Log {
        Log {
            data: VecDeque::with_capacity(size),
            size,
        }
    }

    pub fn read(&self) -> (&[u8], &[u8]) {
        self.data.as_slices()
    }

    pub fn write(&mut self, buf: &[u8]) {
        for &b in buf {
            while self.data.len() + 1 >= self.size {
                self.data.pop_front();
            }
            self.data.push_back(b);
        }
    }
}

pub struct Writer<'a> {
    log: MutexGuard<'a, Option<Log>>,
    display: MutexGuard<'a, Option<DebugDisplay>>,
    arch: crate::arch::debug::Writer<'a>,
}

impl<'a> Writer<'a> {
    pub fn new() -> Writer<'a> {
        Writer {
            log: LOG.lock(),
            display: DEBUG_DISPLAY.lock(),
            arch: crate::arch::debug::Writer::new(),
        }
    }

    pub fn write(&mut self, buf: &[u8], preserve: bool) {
        if preserve {
            if let Some(ref mut log) = *self.log {
                log.write(buf);
            }
        }

        if let Some(display) = &mut *self.display {
            display.write(buf);
        }

        self.arch.write(buf);
    }
}

impl fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        self.write(s.as_bytes(), true);
        Ok(())
    }
}
