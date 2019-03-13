use core::fmt;
#[cfg(feature = "qemu_debug")]
use spin::Mutex;
use spin::MutexGuard;

#[cfg(feature = "qemu_debug")]
use syscall::io::Io;
use syscall::io::Pio;
#[cfg(feature = "serial_debug")]
use devices::uart_16550::SerialPort;

#[cfg(feature = "graphical_debug")]
use super::graphical_debug::{DEBUG_DISPLAY, DebugDisplay};
#[cfg(feature = "serial_debug")]
use super::device::serial::COM1;

#[cfg(feature = "qemu_debug")]
pub static QEMU: Mutex<Pio<u8>> = Mutex::new(Pio::<u8>::new(0x402));

pub struct Writer<'a> {
    #[cfg(feature = "graphical_debug")]
    display: MutexGuard<'a, Option<DebugDisplay>>,
    #[cfg(feature = "qemu_debug")]
    qemu: MutexGuard<'a, Pio<u8>>,
    #[cfg(feature = "serial_debug")]
    serial: MutexGuard<'a, SerialPort<Pio<u8>>>,
}

impl<'a> Writer<'a> {
    pub fn new() -> Writer<'a> {
        Writer {
            #[cfg(feature = "graphical_debug")]
            display: DEBUG_DISPLAY.lock(),
            #[cfg(feature = "qemu_debug")]
            qemu: QEMU.lock(),
            #[cfg(feature = "serial_debug")]
            serial: COM1.lock(),
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        #[cfg(feature = "graphical_debug")]
        {
            if let Some(ref mut display) = *self.display {
                let _ = display.write(buf);
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
    }
}

impl<'a> fmt::Write for Writer<'a> {
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        self.write(s.as_bytes());
        Ok(())
    }
}
