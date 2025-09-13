#[cfg(feature = "qemu_debug")]
use spin::Mutex;
use spin::MutexGuard;

use crate::devices::serial::SerialKind;
#[cfg(feature = "lpss_debug")]
use crate::devices::uart_16550::SerialPort;
#[cfg(feature = "lpss_debug")]
use crate::syscall::io::Mmio;
#[cfg(feature = "qemu_debug")]
use crate::syscall::io::Pio;
#[cfg(feature = "qemu_debug")]
use syscall::io::Io;

use super::device::serial::{COM1, LPSS};
#[cfg(feature = "system76_ec_debug")]
use super::device::system76_ec::{System76Ec, SYSTEM76_EC};

#[cfg(feature = "qemu_debug")]
pub static QEMU: Mutex<Pio<u8>> = Mutex::new(Pio::<u8>::new(0x402));

pub struct Writer<'a> {
    lpss: MutexGuard<'a, SerialKind>,
    #[cfg(feature = "qemu_debug")]
    qemu: MutexGuard<'a, Pio<u8>>,
    serial: MutexGuard<'a, SerialKind>,
    #[cfg(feature = "system76_ec_debug")]
    system76_ec: MutexGuard<'a, Option<System76Ec>>,
}

impl<'a> Writer<'a> {
    pub fn new() -> Writer<'a> {
        Writer {
            lpss: LPSS.lock(),
            #[cfg(feature = "qemu_debug")]
            qemu: QEMU.lock(),
            serial: COM1.lock(),
            #[cfg(feature = "system76_ec_debug")]
            system76_ec: SYSTEM76_EC.lock(),
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        self.lpss.write(buf);

        #[cfg(feature = "qemu_debug")]
        {
            for &b in buf {
                self.qemu.write(b);
            }
        }

        self.serial.write(buf);

        #[cfg(feature = "system76_ec_debug")]
        {
            if let Some(ref mut system76_ec) = *self.system76_ec {
                system76_ec.print_slice(buf);
            }
        }
    }
}
