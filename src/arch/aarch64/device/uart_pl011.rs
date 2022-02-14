use core::fmt::{self, Write};
use core::ptr;

use crate::device::gic;
use crate::scheme::debug::{debug_input, debug_notify};

bitflags! {
    /// UARTFR
    struct UartFrFlags: u16 {
        const TXFE = 1 << 7;
        const RXFF = 1 << 6;
        const TXFF = 1 << 5;
        const RXFE = 1 << 4;
        const BUSY = 1 << 3;
    }
}

bitflags! {
    /// UARTCR
    struct UartCrFlags: u16 {
        const RXE = 1 << 9;
        const TXE = 1 << 8;
        const UARTEN = 1 << 0;
    }
}

bitflags! {
    // UARTIMSC
    struct UartImscFlags: u16 {
        const RTIM = 1 << 6;
        const TXIM = 1 << 5;
        const RXIM = 1 << 4;
    }
}

bitflags! {
    // UARTICR
    struct UartIcrFlags: u16 {
        const RTIC = 1 << 6;
        const TXIC = 1 << 5;
        const RXIC = 1 << 4;
    }
}

bitflags! {
    //UARTMIS
    struct UartMisFlags: u16 {
        const TXMIS = 1 << 5;
        const RXMIS = 1 << 4;
    }
}

bitflags! {
    //UARTLCR_H
    struct UartLcrhFlags: u16 {
        const FEN = 1 << 4;
    }
}

#[allow(dead_code)]
pub struct SerialPort {
    base: usize,
    data_reg: u8,
    rcv_stat_reg: u8,
    flag_reg: u8,
    int_baud_reg: u8,
    frac_baud_reg: u8,
    line_ctrl_reg: u8,
    ctrl_reg: u8,
    intr_fifo_ls_reg: u8,
    intr_mask_setclr_reg: u8,
    raw_intr_stat_reg: u8,
    masked_intr_stat_reg: u8,
    intr_clr_reg: u8,
    dma_ctrl_reg: u8
}

impl SerialPort {
    pub const fn new(base: usize) -> SerialPort {
        SerialPort {
            base: base,
            data_reg: 0x00,
            rcv_stat_reg: 0x04,
            flag_reg: 0x18,
            int_baud_reg: 0x24,
            frac_baud_reg: 0x28,
            line_ctrl_reg: 0x2c,
            ctrl_reg: 0x30,
            intr_fifo_ls_reg: 0x34,
            intr_mask_setclr_reg: 0x38,
            raw_intr_stat_reg: 0x3c,
            masked_intr_stat_reg: 0x40,
            intr_clr_reg: 0x44,
            dma_ctrl_reg: 0x48,
        }
    }

    pub fn base(&self) -> usize {
        self.base
    }

    pub fn read_reg(&self, register: u8) -> u16 {
        unsafe { ptr::read_volatile((self.base + register as usize) as *mut u16) }
    }

    pub fn write_reg(&self, register: u8, data: u16) {
        unsafe { ptr::write_volatile((self.base + register as usize) as *mut u16, data); }
    }

    pub fn init(&mut self, with_irq: bool) {
        // Enable RX, TX, UART
        let flags = UartCrFlags::RXE | UartCrFlags::TXE | UartCrFlags::UARTEN;
        self.write_reg(self.ctrl_reg, flags.bits());

        // Disable FIFOs (use character mode instead)
        let mut flags = UartLcrhFlags::from_bits_truncate(self.read_reg(self.line_ctrl_reg));
        flags.remove(UartLcrhFlags::FEN);
        self.write_reg(self.line_ctrl_reg, flags.bits());

        if with_irq {
            // Enable IRQs
            let flags = UartImscFlags::RXIM;
            self.write_reg(self.intr_mask_setclr_reg, flags.bits);

            // Clear pending interrupts
            self.write_reg(self.intr_clr_reg, 0x7ff);

            // Enable interrupt at GIC distributor
            gic::irq_enable(33);
        }
    }

    fn line_sts(&self) -> UartFrFlags {
        UartFrFlags::from_bits_truncate(self.read_reg(self.flag_reg))
    }

    pub fn receive(&mut self) {
        while self.line_sts().contains(UartFrFlags::RXFF) {
            debug_input(self.read_reg(self.data_reg) as u8);
        }
        debug_notify();
    }

    pub fn send(&mut self, data: u8) {
        while ! self.line_sts().contains(UartFrFlags::TXFE) {}
        self.write_reg(self.data_reg, data as u16);
    }

    pub fn clear_all_irqs(&mut self) {
        let flags = UartIcrFlags::RXIC;
        self.write_reg(self.intr_clr_reg, flags.bits());
    }

    pub fn disable_irq(&mut self) {
        self.write_reg(self.intr_mask_setclr_reg, 0);
    }

    pub fn enable_irq(&mut self) {
        let flags = UartImscFlags::RXIM;
        self.write_reg(self.intr_mask_setclr_reg, flags.bits());
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
