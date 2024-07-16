use crate::syscall::io::{Io, Pio};

pub static mut CHAN0: Pio<u8> = Pio::new(0x40);
//pub static mut CHAN1: Pio<u8> = Pio::new(0x41);
//pub static mut CHAN2: Pio<u8> = Pio::new(0x42);
pub static mut COMMAND: Pio<u8> = Pio::new(0x43);

const SELECT_CHAN0: u8 = 0b00 << 6;
const ACCESS_LATCH: u8 = 0b00 << 4;
const ACCESS_LOHI: u8 = 0b11 << 4;
const MODE_2: u8 = 0b010 << 1;

// 1 / (1.193182 MHz) = 838,095,110 femtoseconds ~= 838.095 ns
pub const PERIOD_FS: u128 = 838_095_110;

// 4847 / (1.193182 MHz) = 4,062,247 ns ~= 4.1 ms or 246 Hz
pub const CHAN0_DIVISOR: u16 = 4847;

// Calculated interrupt period in nanoseconds based on divisor and period
pub const RATE: u128 = (CHAN0_DIVISOR as u128 * PERIOD_FS) / 1_000_000;

pub unsafe fn init() {
    COMMAND.write(SELECT_CHAN0 | ACCESS_LOHI | MODE_2);
    CHAN0.write(CHAN0_DIVISOR as u8);
    CHAN0.write((CHAN0_DIVISOR >> 8) as u8);
}

pub unsafe fn read() -> u16 {
    COMMAND.write(SELECT_CHAN0 | ACCESS_LATCH);
    let low = CHAN0.read();
    let high = CHAN0.read();
    let counter = ((high as u16) << 8) | (low as u16);
    // Counter is inverted, subtract from CHAN0_DIVISOR
    CHAN0_DIVISOR.saturating_sub(counter)
}
