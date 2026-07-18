use core::ptr;

use crate::{
    scheme::debug::{debug_input, debug_notify},
    sync::CleanLockToken,
};

// AML_UART_CONTROL (0x08) is read-modify-written as a raw u32 instead of
// via bitflags, since the register has fields we don't declare (data
// length, parity, stop bits) that from_bits_truncate() would wipe out.
mod control {
    pub const TX_EN: u32 = 1 << 12;
    pub const RX_EN: u32 = 1 << 13;
    pub const TWO_WIRE_EN: u32 = 1 << 15;
    pub const STOP_BIT_LEN_MASK: u32 = 0x03 << 16;
    pub const PARITY_TYPE: u32 = 1 << 18;
    pub const PARITY_EN: u32 = 1 << 19;
    pub const DATA_LEN_MASK: u32 = 0x03 << 20;
    pub const TX_RST: u32 = 1 << 22;
    pub const RX_RST: u32 = 1 << 23;
    pub const CLEAR_ERR: u32 = 1 << 24;
    pub const RX_INT_EN: u32 = 1 << 27;
    pub const TX_INT_EN: u32 = 1 << 28;
}

bitflags! {
    /// AML_UART_STATUS (0x0c), read-only.
    #[derive(Clone, Copy, Debug)]
    struct UartStatusFlags: u32 {
        const PARITY_ERR = 1 << 16;
        const FRAME_ERR = 1 << 17;
        const TX_FIFO_WERR = 1 << 18;
        const RX_EMPTY = 1 << 20;
        const TX_FULL = 1 << 21;
        const TX_EMPTY = 1 << 22;
        const XMIT_BUSY = 1 << 25;
        const RX_ERR = Self::PARITY_ERR.bits() | Self::FRAME_ERR.bits();
        const ERR = Self::RX_ERR.bits() | Self::TX_FIFO_WERR.bits();
    }
}

bitflags! {
    /// AML_UART_REG5 (0x14).
    #[derive(Clone, Copy, Debug)]
    struct UartBaudFlags: u32 {
        const USE_NEW_BAUD_RATE = 1 << 23;
        const XTAL_CLK = 1 << 24;
        /// Variants currently recognized as using the XTAL /2 divider:
        /// G12A and S4.
        const XTAL_DIV2 = 1 << 27;
    }
}

const BAUD_DIVISOR_MASK: u32 = 0x7f_ffff;
const XTAL_HZ: u32 = 24_000_000;
const TX_IDLE_POLL_LIMIT: usize = 1_000_000;

/// Clock divider used to derive the baud rate from the 24 MHz XTAL.
/// Varies by SoC generation, so it's per-instance, not a global constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockVariant {
    /// Variants selected by the explicit /3 compatible list.
    XtalDiv3,
    /// Variants currently recognized as using the XTAL /2 divider:
    /// G12A and S4.
    XtalDiv2,
}

impl ClockVariant {
    pub fn from_compatible(compatible: &str) -> Option<ClockVariant> {
        let mut generic_fallback = None;

        for value in compatible.split('\0') {
            match value {
                "amlogic,meson-g12a-uart" | "amlogic,meson-s4-uart" => {
                    return Some(ClockVariant::XtalDiv2);
                }
                "amlogic,meson6-uart"
                | "amlogic,meson8-uart"
                | "amlogic,meson8b-uart"
                | "amlogic,meson-gx-uart"
                | "amlogic,meson-a1-uart" => return Some(ClockVariant::XtalDiv3),
                // The generic compatible is a /3 fallback when no recognized
                // SoC-specific compatible determines the divider.
                "amlogic,meson-uart" => {
                    generic_fallback = Some(ClockVariant::XtalDiv3);
                }
                _ => {}
            }
        }

        generic_fallback
    }
}

pub fn is_compatible(compatible: &str) -> bool {
    ClockVariant::from_compatible(compatible).is_some()
}

pub fn uses_vendor_clock_binding(compatible: &str) -> bool {
    let mut has_generic = false;
    for value in compatible.split('\0') {
        match value {
            "amlogic,meson-uart" => has_generic = true,
            "amlogic,meson6-uart"
            | "amlogic,meson8-uart"
            | "amlogic,meson8b-uart"
            | "amlogic,meson-gx-uart"
            | "amlogic,meson-g12a-uart"
            | "amlogic,meson-s4-uart"
            | "amlogic,meson-a1-uart" => return false,
            _ => {}
        }
    }
    has_generic
}

fn calculate_baud_divisor(baud_rate: u32, clock_variant: ClockVariant) -> Option<u32> {
    if baud_rate == 0 {
        return None;
    }
    let xtal_div = match clock_variant {
        ClockVariant::XtalDiv3 => 3,
        ClockVariant::XtalDiv2 => 2,
    };
    let base_clk = XTAL_HZ / xtal_div;
    let rounded = base_clk.checked_add(baud_rate / 2)? / baud_rate;
    let divisor = rounded.checked_sub(1)?;
    (divisor <= BAUD_DIVISOR_MASK).then_some(divisor)
}

pub struct SerialPort {
    base: usize,
    wfifo_reg: u8,
    rfifo_reg: u8,
    control_reg: u8,
    status_reg: u8,
    misc_reg: u8,
    baud_reg: u8,
    baud_rate: u32,
    clock_variant: ClockVariant,
    skip_init: bool,
    /// Hardware FIFO depth; defaults to 64 when the DT omits it.
    fifo_size: u32,
}

impl SerialPort {
    /// # Safety
    ///
    /// `base` must be an aligned, mapped MMIO range of at least 0x18 bytes
    /// that exclusively represents a Meson UART for the lifetime of the port.
    pub const unsafe fn new(
        base: usize,
        baud_rate: u32,
        clock_variant: ClockVariant,
        fifo_size: u32,
        skip_init: bool,
    ) -> SerialPort {
        SerialPort {
            base,
            wfifo_reg: 0x00,
            rfifo_reg: 0x04,
            control_reg: 0x08,
            status_reg: 0x0c,
            misc_reg: 0x10,
            baud_reg: 0x14,
            baud_rate,
            clock_variant,
            skip_init,
            fifo_size,
        }
    }

    fn read_reg(&self, register: u8) -> u32 {
        unsafe { ptr::read_volatile((self.base + register as usize) as *const u32) }
    }

    fn write_reg(&self, register: u8, data: u32) {
        unsafe {
            ptr::write_volatile((self.base + register as usize) as *mut u32, data);
        }
    }

    fn status(&self) -> UartStatusFlags {
        UartStatusFlags::from_bits_truncate(self.read_reg(self.status_reg))
    }

    fn control_set(&self, mask: u32) {
        let val = self.read_reg(self.control_reg);
        self.write_reg(self.control_reg, val | mask);
    }

    fn control_clear(&self, mask: u32) {
        let val = self.read_reg(self.control_reg);
        self.write_reg(self.control_reg, val & !mask);
    }

    /// Enables TX while preserving the serial configuration left by firmware.
    /// This can be called before the FIFO, baud-rate, and interrupt
    /// configuration has been validated.
    pub fn init_early(&mut self) {
        self.control_set(control::TX_EN);
    }

    fn baud_divisor(&self) -> Option<u32> {
        calculate_baud_divisor(self.baud_rate, self.clock_variant)
    }

    /// Resets FIFOs, programs baud/format/IRQ thresholds, enables RX/TX.
    /// Call only after `init_early()` and only with a correct
    /// `clock_variant`/`fifo_size` for the real hardware.
    pub fn init_full(&mut self) -> Result<(), ()> {
        if self.skip_init {
            return Ok(());
        }

        let div = self.baud_divisor().ok_or(())?;

        // !TX_FULL alone isn't enough here: it only means the FIFO has
        // room, not that the shifter has actually stopped.
        let mut idle = false;
        for _ in 0..TX_IDLE_POLL_LIMIT {
            let status = self.status();
            if status.contains(UartStatusFlags::TX_EMPTY)
                && !status.contains(UartStatusFlags::XMIT_BUSY)
            {
                idle = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !idle {
            return Err(());
        }

        self.control_set(control::TX_RST | control::RX_RST | control::CLEAR_ERR);
        self.control_clear(control::TX_RST | control::RX_RST | control::CLEAR_ERR);

        let mut baud = (UartBaudFlags::USE_NEW_BAUD_RATE | UartBaudFlags::XTAL_CLK).bits() | div;
        if self.clock_variant == ClockVariant::XtalDiv2 {
            baud |= UartBaudFlags::XTAL_DIV2.bits();
        }
        self.write_reg(self.baud_reg, baud);

        const RX_IRQ_THRESHOLD: u32 = 1;

        let tx_irq_threshold = self.fifo_size / 2;
        self.write_reg(
            self.misc_reg,
            RX_IRQ_THRESHOLD | (tx_irq_threshold << 8),
        );

        let mut control = self.read_reg(self.control_reg);
        control &= !(control::STOP_BIT_LEN_MASK
            | control::PARITY_TYPE
            | control::PARITY_EN
            | control::DATA_LEN_MASK
            | control::TX_INT_EN
            | control::RX_INT_EN);
        control |= control::TX_EN | control::RX_EN | control::TWO_WIRE_EN;
        self.write_reg(self.control_reg, control);

        self.drain_fifo();

        Ok(())
    }

    fn clear_errors(&mut self) {
        self.control_set(control::CLEAR_ERR);
        self.control_clear(control::CLEAR_ERR);
    }

    pub fn drain_fifo(&mut self) {
        for _ in 0..self.fifo_size.saturating_mul(2) {
            if self.status().contains(UartStatusFlags::RX_EMPTY) {
                break;
            }
            let _ = self.read_reg(self.rfifo_reg);
        }
    }

    pub fn receive(&mut self, token: &mut CleanLockToken) {
        let mut received = false;

        for _ in 0..256 {
            let status = self.status();
            let rx_error = status.intersects(UartStatusFlags::RX_ERR);
            if status.intersects(UartStatusFlags::ERR) {
                self.clear_errors();
            }
            if status.contains(UartStatusFlags::RX_EMPTY) {
                break;
            }

            let c = self.read_reg(self.rfifo_reg) as u8;
            if !rx_error && c != 0 {
                debug_input(c, token);
                received = true;
            }
        }

        if received {
            debug_notify(token);
        }
    }

    pub fn send(&mut self, data: u8) {
        while self.status().contains(UartStatusFlags::TX_FULL) {}
        self.write_reg(self.wfifo_reg, data as u32);
    }

    pub fn enable_irq(&mut self) {
        // skip-init preserves the baud rate, format, and FIFO configuration
        // supplied by firmware. Interrupt setup still takes ownership of RX.
        self.clear_errors();
        self.drain_fifo();

        self.control_clear(control::TX_INT_EN);
        self.control_set(control::RX_INT_EN | control::RX_EN | control::TX_EN);
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
                _ => self.send(b),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{calculate_baud_divisor, is_compatible, uses_vendor_clock_binding, ClockVariant};

    #[test]
    fn recognizes_vendor_and_upstream_compatibles() {
        assert!(is_compatible("amlogic,meson-uart"));
        assert!(is_compatible("amlogic,meson-s4-uart"));
        assert!(is_compatible(
            "amlogic,meson-s4-uart\0amlogic,meson-ao-uart"
        ));
        assert!(!is_compatible("amlogic,meson-ao-uart"));
        assert!(!is_compatible("amlogic,meson-gpio"));
        assert!(!is_compatible("amlogic,meson-future-uart"));
    }

    #[test]
    fn generic_binding_uses_xtal_divide_by_three() {
        assert_eq!(
            ClockVariant::from_compatible("amlogic,meson-uart"),
            Some(ClockVariant::XtalDiv3)
        );
        assert_eq!(
            ClockVariant::from_compatible("amlogic,meson-s4-uart\0amlogic,meson-uart"),
            Some(ClockVariant::XtalDiv2)
        );
        assert_eq!(
            ClockVariant::from_compatible("amlogic,meson-sc2-uart"),
            None
        );
    }

    #[test]
    fn calculates_xtal_divisors_for_921600_baud() {
        assert_eq!(
            calculate_baud_divisor(921_600, ClockVariant::XtalDiv3),
            Some(8)
        );
        assert_eq!(
            calculate_baud_divisor(921_600, ClockVariant::XtalDiv2),
            Some(12)
        );
        assert_eq!(calculate_baud_divisor(0, ClockVariant::XtalDiv3), None);
    }

    #[test]
    fn vendor_clock_binding_does_not_override_specific_compatible() {
        assert!(uses_vendor_clock_binding("amlogic,meson-uart"));
        assert!(!uses_vendor_clock_binding(
            "amlogic,meson-s4-uart\0amlogic,meson-uart"
        ));
    }
}
