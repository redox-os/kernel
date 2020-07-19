use core::fmt;
#[cfg(feature = "qemu_debug")]
use spin::Mutex;
use spin::MutexGuard;

use crate::log::{LOG, Log};
#[cfg(feature = "qemu_debug")]
use syscall::io::Io;
#[cfg(any(feature = "qemu_debug", feature = "serial_debug"))]
use crate::syscall::io::Pio;
#[cfg(feature = "lpss_debug")]
use crate::syscall::io::Mmio;
#[cfg(any(feature = "lpss_debug", feature = "serial_debug"))]
use crate::devices::uart_16550::SerialPort;

#[cfg(feature = "graphical_debug")]
use super::graphical_debug::{DEBUG_DISPLAY, DebugDisplay};
#[cfg(feature = "lpss_debug")]
use super::device::serial::LPSS;
#[cfg(feature = "serial_debug")]
use super::device::serial::COM1;
#[cfg(feature = "system76_ec_debug")]
use super::device::system76_ec::{SYSTEM76_EC, System76Ec};

#[cfg(feature = "qemu_debug")]
pub static QEMU: Mutex<Pio<u8>> = Mutex::new(Pio::<u8>::new(0x402));

pub struct Writer<'a> {
    log: MutexGuard<'a, Option<Log>>,
    #[cfg(feature = "graphical_debug")]
    display: MutexGuard<'a, Option<DebugDisplay>>,
    #[cfg(feature = "lpss_debug")]
    lpss: MutexGuard<'a, Option<&'static mut SerialPort<Mmio<u32>>>>,
    #[cfg(feature = "qemu_debug")]
    qemu: MutexGuard<'a, Pio<u8>>,
    #[cfg(feature = "serial_debug")]
    serial: MutexGuard<'a, SerialPort<Pio<u8>>>,
    #[cfg(feature = "system76_ec_debug")]
    system76_ec: MutexGuard<'a, Option<System76Ec>>,
}

impl<'a> Writer<'a> {
    pub fn new() -> Writer<'a> {
        Writer {
            log: LOG.lock(),
            #[cfg(feature = "graphical_debug")]
            display: DEBUG_DISPLAY.lock(),
            #[cfg(feature = "lpss_debug")]
            lpss: LPSS.lock(),
            #[cfg(feature = "qemu_debug")]
            qemu: QEMU.lock(),
            #[cfg(feature = "serial_debug")]
            serial: COM1.lock(),
            #[cfg(feature = "system76_ec_debug")]
            system76_ec: SYSTEM76_EC.lock(),
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        {
            if let Some(ref mut log) = *self.log {
                log.write(buf);
            }
        }

        #[cfg(feature = "graphical_debug")]
        {
            if let Some(ref mut display) = *self.display {
                let _ = display.write(buf);
            }
        }

        #[cfg(feature = "lpss_debug")]
        {
            if let Some(ref mut lpss) = *self.lpss {
                lpss.write(buf);
            }
        }

        #[cfg(feature = "qemu_debug")]
        {
            for &b in buf {
                self.qemu.write(b);
            }
        }

        #[cfg(feature = "serial_debug")]
        {
            self.serial.write(buf);
        }

        #[cfg(feature = "system76_ec_debug")]
        {
            if let Some(ref mut system76_ec) = *self.system76_ec {
                system76_ec.print_slice(buf);
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
