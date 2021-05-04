use core::fmt;
use spin::MutexGuard;

use crate::log::{LOG, Log};

#[cfg(feature = "serial_debug")]
use super::device::{
    serial::COM1,
    uart_pl011::SerialPort,
};

pub struct Writer<'a> {
    log: MutexGuard<'a, Option<Log>>,
    #[cfg(feature = "serial_debug")]
    serial: MutexGuard<'a, Option<SerialPort>>,
}

impl<'a> Writer<'a> {
    pub fn new() -> Writer<'a> {
        Writer {
            log: LOG.lock(),
            #[cfg(feature = "serial_debug")]
            serial: COM1.lock(),
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        {
            if let Some(ref mut log) = *self.log {
                log.write(buf);
            }
        }

        #[cfg(feature = "serial_debug")]
        {
            if let Some(ref mut serial) = *self.serial {
                serial.write(buf);
            }
        }
    }
}

impl<'a> fmt::Write for Writer<'a> {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        self.write(s.as_bytes());
        Ok(())
    }
}
