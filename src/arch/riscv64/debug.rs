use spin::MutexGuard;

use crate::{device::serial::COM1, devices::serial::SerialKind};

pub struct Writer<'a> {
    serial: MutexGuard<'a, Option<SerialKind>>,
}

impl<'a> Writer<'a> {
    pub fn new() -> Writer<'a> {
        Writer {
            serial: COM1.lock(),
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        if let Some(ref mut serial) = *self.serial {
            serial.write(buf);
        }
    }
}
