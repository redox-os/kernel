use crate::syscall::io::{Io, Pio};

pub static mut CHAN0: Pio<u8> = Pio::new(0x40);
pub static mut CHAN1: Pio<u8> = Pio::new(0x41);
pub static mut CHAN2: Pio<u8> = Pio::new(0x42);
pub static mut COMMAND: Pio<u8> = Pio::new(0x43);

const SELECT_CHAN0: u8 = 0b00 << 6;
const ACCESS_LATCH: u8 = 0b00 << 4;
const ACCESS_LOHI: u8 = 0b11 << 4;
const MODE_2: u8 = 0b010 << 1;

const CHAN0_DIVISOR: u16 = 2685;

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
