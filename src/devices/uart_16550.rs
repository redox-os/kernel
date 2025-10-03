#![allow(unused)]

use core::{
    convert::TryInto,
    ptr::{addr_of, addr_of_mut},
};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::syscall::io::Pio;
use crate::syscall::io::{Io, Mmio, ReadOnly};

bitflags! {
    /// Interrupt enable flags
    struct IntEnFlags: u8 {
        const RECEIVED = 1;
        const SENT = 1 << 1;
        const ERRORED = 1 << 2;
        const STATUS_CHANGE = 1 << 3;
        // 4 to 7 are unused
    }
}

bitflags! {
    /// Line status flags
    struct LineStsFlags: u8 {
        const INPUT_FULL = 1;
        // 1 to 4 unknown
        const OUTPUT_EMPTY = 1 << 5;
        // 6 and 7 unknown
    }
}

#[allow(dead_code)]
#[repr(packed(4))]
pub struct SerialPort<T: Io> {
    /// Data register, read to receive, write to send
    data: T,
    /// Interrupt enable
    int_en: T,
    /// FIFO control
    fifo_ctrl: T,
    /// Line control
    line_ctrl: T,
    /// Modem control
    modem_ctrl: T,
    /// Line status
    line_sts: ReadOnly<T>,
    /// Modem status
    modem_sts: ReadOnly<T>,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl SerialPort<Pio<u8>> {
    pub const fn new(base: u16) -> SerialPort<Pio<u8>> {
        SerialPort {
            data: Pio::new(base),
            int_en: Pio::new(base + 1),
            fifo_ctrl: Pio::new(base + 2),
            line_ctrl: Pio::new(base + 3),
            modem_ctrl: Pio::new(base + 4),
            line_sts: ReadOnly::new(Pio::new(base + 5)),
            modem_sts: ReadOnly::new(Pio::new(base + 6)),
        }
    }
}

impl SerialPort<Mmio<u32>> {
    #[allow(dead_code)]
    pub unsafe fn new(base: usize) -> &'static mut SerialPort<Mmio<u32>> {
        unsafe { &mut *(base as *mut Self) }
    }
}

impl SerialPort<Mmio<u8>> {
    #[allow(dead_code)]
    pub unsafe fn new(base: usize) -> &'static mut SerialPort<Mmio<u8>> {
        unsafe { &mut *(base as *mut Self) }
    }
}

impl<T: Io> SerialPort<T>
where
    T::Value: From<u8> + TryInto<u8>,
{
    pub fn init(&mut self) -> Result<(), ()> {
        unsafe {
            //TODO: Cleanup
            // FIXME: Fix UB if unaligned
            // Disable all interrupts
            (&mut *addr_of_mut!(self.int_en)).write(0x00.into());
            // Set baud rate divisor
            (&mut *addr_of_mut!(self.line_ctrl)).write(0x80.into());
            // Set divisor to 1 (115200 baud)
            (&mut *addr_of_mut!(self.data)).write(0x01.into());
            (&mut *addr_of_mut!(self.int_en)).write(0x00.into());
            // Use 8 data bits, no parity, one stop bit
            (&mut *addr_of_mut!(self.line_ctrl)).write(0x03.into());
            // Enable and clear FIFOs with 14-byte threshold
            (&mut *addr_of_mut!(self.fifo_ctrl)).write(0xC7.into());

            // Enable loopback
            (&mut *addr_of_mut!(self.modem_ctrl)).write(0x10.into());
            // Perform loopback test with even/odd pattern
            for &byte in &[0x55, 0xAA] {
                (&mut *addr_of_mut!(self.data)).write(byte.into());
                if (&mut *addr_of_mut!(self.data)).read() != byte.into() {
                    return Err(());
                }
            }

            // Enable DTR, RTS, OUT1, and OUT2, disable loopback
            (&mut *addr_of_mut!(self.modem_ctrl)).write(0x0F.into());
            // Enable receive interrupt
            (&mut *addr_of_mut!(self.int_en)).write(0x01.into());
        }

        Ok(())
    }

    fn line_sts(&self) -> LineStsFlags {
        LineStsFlags::from_bits_truncate(
            (unsafe { &*addr_of!(self.line_sts) }.read() & 0xFF.into())
                .try_into()
                .unwrap_or(0),
        )
    }

    pub fn receive(&mut self) -> Option<u8> {
        if self.line_sts().contains(LineStsFlags::INPUT_FULL) {
            Some(
                (unsafe { &*addr_of!(self.data) }.read() & 0xFF.into())
                    .try_into()
                    .unwrap_or(0),
            )
        } else {
            None
        }
    }

    pub fn send(&mut self, data: u8) {
        while !self.line_sts().contains(LineStsFlags::OUTPUT_EMPTY) {}
        unsafe { &mut *addr_of_mut!(self.data) }.write(data.into())
    }

    pub fn write(&mut self, buf: &[u8]) {
        for &b in buf {
            match b {
                8 | 0x7F => {
                    self.send(8);
                    self.send(b' ');
                    self.send(8);
                }
                b'\n' => {
                    self.send(b'\r');
                    self.send(b'\n');
                }
                _ => {
                    self.send(b);
                }
            }
        }
    }
}
