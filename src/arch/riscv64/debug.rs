use core::fmt;
use spin::MutexGuard;

use crate::log::{LOG, Log};

pub struct Writer<'a> {
    log: MutexGuard<'a, Option<Log>>,
}

impl<'a> Writer<'a> {
    pub fn new() -> Writer<'a> {
        Writer {
            log: LOG.lock(),
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        {
            if let Some(ref mut log) = *self.log {
                log.write(buf);
            }
        }

        //TODO: serial port
    }
}

impl<'a> fmt::Write for Writer<'a> {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        self.write(s.as_bytes());
        Ok(())
    }
}
