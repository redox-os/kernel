use core::ptr;

use crate::scheme::debug::{debug_input, debug_notify};

bitflags! {
    /// UARTFR
    #[derive(Clone, Copy, Debug)]
    struct UartFrFlags: u32 {
        const TXFE = 1 << 7;
        const RXFF = 1 << 6;
        const TXFF = 1 << 5;
        const RXFE = 1 << 4;
        const BUSY = 1 << 3;
    }
}

bitflags! {
    /// UARTCR
    #[derive(Clone, Copy, Debug)]
    struct UartCrFlags: u32 {
        const RXE = 1 << 9;
        const TXE = 1 << 8;
        const UARTEN = 1 << 0;
    }
}

bitflags! {
    // UARTIMSC
    #[derive(Clone, Copy, Debug)]
    struct UartImscFlags: u32 {
        const RTIM = 1 << 6;
        const TXIM = 1 << 5;
        const RXIM = 1 << 4;
    }
}

bitflags! {
    // UARTICR
    #[derive(Clone, Copy, Debug)]
    struct UartIcrFlags: u32 {
        const RTIC = 1 << 6;
        const TXIC = 1 << 5;
        const RXIC = 1 << 4;
    }
}

bitflags! {
    // UARTRIS
    #[derive(Clone, Copy, Debug)]
    struct UartRisFlags: u32 {
        const RTIS = 1 << 6;
        const TXIS = 1 << 5;
        const RXIS = 1 << 4;
    }
}

bitflags! {
    //UARTMIS
    #[derive(Clone, Copy, Debug)]
    struct UartMisFlags: u32 {
        const TXMIS = 1 << 5;
        const RXMIS = 1 << 4;
    }
}

bitflags! {
    //UARTLCR_H
    #[derive(Clone, Copy, Debug)]
    struct UartLcrhFlags: u32 {
        const FEN = 1 << 4;
    }
}

bitflags! {
    //UARTIFLS
    #[derive(Clone, Copy, Debug)]
    struct UartIflsFlags: u32 {
        const RX1_8 = 0 << 3;
        const RX2_8 = 1 << 3;
        const RX4_8 = 2 << 3;
        const RX6_8 = 3 << 3;
        const RX7_8 = 4 << 3;
        const TX1_8 = 0 << 0;
        const TX2_8 = 1 << 0;
        const TX4_8 = 2 << 0;
        const TX6_8 = 3 << 0;
        const TX7_8 = 4 << 0;
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
    ifls_reg: u8,
    intr_mask_setclr_reg: u8,
    raw_intr_stat_reg: u8,
    masked_intr_stat_reg: u8,
    intr_clr_reg: u8,
    dma_ctrl_reg: u8,
    ifls: u32,
    fifo_size: u32,
    cts_event_walkaround: bool,
}

impl SerialPort {
    pub const fn new(base: usize, cts_event_walkaround: bool) -> SerialPort {
        SerialPort {
            base: base,
            data_reg: 0x00,
            rcv_stat_reg: 0x04,
            flag_reg: 0x18,
            int_baud_reg: 0x24,
            frac_baud_reg: 0x28,
            line_ctrl_reg: 0x2c,
            ctrl_reg: 0x30,
            ifls_reg: 0x34,
            intr_mask_setclr_reg: 0x38,
            raw_intr_stat_reg: 0x3c,
            masked_intr_stat_reg: 0x40,
            intr_clr_reg: 0x44,
            dma_ctrl_reg: 0x48,
            ifls: 0x12, // RX4_8 | TX4_8
            fifo_size: 32,
            cts_event_walkaround: cts_event_walkaround,
        }
    }

    pub fn read_reg(&self, register: u8) -> u32 {
        unsafe { ptr::read_volatile((self.base + register as usize) as *mut u32) }
    }

    pub fn write_reg(&self, register: u8, data: u32) {
        unsafe {
            ptr::write_volatile((self.base + register as usize) as *mut u32, data);
        }
    }

    pub fn init(&mut self, with_irq: bool) {
        //Disable UART first
        self.write_reg(self.ctrl_reg, 0x0);

        //Setup ifls
        self.write_reg(self.ifls_reg, self.ifls);

        //Enable FIFO
        if self.fifo_size > 1 {
            let mut flags = UartLcrhFlags::from_bits_truncate(self.read_reg(self.line_ctrl_reg));
            flags |= UartLcrhFlags::FEN;
            self.write_reg(self.line_ctrl_reg, flags.bits());
        }

        // Enable RX, TX, UART
        let flags = UartCrFlags::RXE | UartCrFlags::TXE | UartCrFlags::UARTEN;
        self.write_reg(self.ctrl_reg, flags.bits());

        if with_irq {
            self.enable_irq();
        }
    }

    fn line_sts(&self) -> UartFrFlags {
        UartFrFlags::from_bits_truncate(self.read_reg(self.flag_reg))
    }

    fn intr_stats(&self) -> UartRisFlags {
        UartRisFlags::from_bits_truncate(self.read_reg(self.raw_intr_stat_reg))
    }

    pub fn drain_fifo(&mut self) {
        for _ in 0..self.fifo_size * 2 {
            if self.line_sts().contains(UartFrFlags::RXFE) {
                break;
            }
            let _ = self.read_reg(self.data_reg);
        }
    }

    pub fn receive(&mut self) {
        let mut flags = self.intr_stats();
        let chk_flags = UartRisFlags::RTIS | UartRisFlags::RXIS;
        while (flags & chk_flags).bits() != 0 {
            if self.cts_event_walkaround {
                self.write_reg(self.intr_clr_reg, 0x00);
                let _ = self.read_reg(self.intr_clr_reg);
                let _ = self.read_reg(self.intr_clr_reg);
            }

            let clr = flags & (!chk_flags);
            self.write_reg(self.intr_clr_reg, clr.bits());

            for _ in 0..256 {
                if self.line_sts().contains(UartFrFlags::RXFE) {
                    break;
                }
                let c = self.read_reg(self.data_reg) as u8;
                if c != 0 {
                    debug_input(c);
                }
            }

            flags = self.intr_stats();
        }
        debug_notify();
    }

    pub fn send(&mut self, data: u8) {
        while !self.line_sts().contains(UartFrFlags::TXFE) {}
        self.write_reg(self.data_reg, data as u32);
    }

    pub fn clear_all_irqs(&mut self) {
        let flags = UartIcrFlags::RTIC | UartIcrFlags::RXIC;
        self.write_reg(self.intr_clr_reg, flags.bits());
    }

    pub fn enable_irq(&mut self) {
        self.clear_all_irqs();

        self.drain_fifo();

        let flags = UartImscFlags::RXIM | UartImscFlags::RTIM;
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
