use syscall::Mmio;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use syscall::Pio;

use crate::{
    devices::{uart_16550, uart_pl011},
    scheme::debug::{debug_input, debug_notify},
    sync::CleanLockToken,
};

#[allow(dead_code)]
pub enum SerialKind {
    NotPresent,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Ns16550Pio(uart_16550::SerialPort<Pio<u8>>),
    Ns16550u8(&'static mut uart_16550::SerialPort<Mmio<u8>>),
    Ns16550u32(&'static mut uart_16550::SerialPort<Mmio<u32>>),
    Pl011(uart_pl011::SerialPort),
}

impl SerialKind {
    #[cfg(target_arch = "aarch64")]
    pub fn enable_irq(&mut self) {
        //TODO: implement for NS16550
        match self {
            Self::NotPresent => {}
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::Ns16550Pio(_) => {}
            Self::Ns16550u8(_) => {}
            Self::Ns16550u32(_) => {}
            Self::Pl011(inner) => inner.enable_irq(),
        }
    }

    pub fn receive(&mut self, token: &mut CleanLockToken) {
        //TODO: make PL011 receive work the same way as NS16550
        match self {
            Self::NotPresent => {}
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::Ns16550Pio(inner) => {
                while let Some(c) = inner.receive() {
                    debug_input(c, token);
                }
                debug_notify(token);
            }
            Self::Ns16550u8(inner) => {
                while let Some(c) = inner.receive() {
                    debug_input(c, token);
                }
                debug_notify(token);
            }
            Self::Ns16550u32(inner) => {
                while let Some(c) = inner.receive() {
                    debug_input(c, token);
                }
                debug_notify(token);
            }
            Self::Pl011(inner) => inner.receive(token),
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        match self {
            Self::NotPresent => {}
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::Ns16550Pio(inner) => inner.write(buf),
            Self::Ns16550u8(inner) => inner.write(buf),
            Self::Ns16550u32(inner) => inner.write(buf),
            Self::Pl011(inner) => inner.write(buf),
        }
    }
}
