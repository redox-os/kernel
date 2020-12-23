use crate::syscall::io::{Io, Pio};

pub static mut CHAN0: Pio<u8> = Pio::new(0x40);
pub static mut CHAN1: Pio<u8> = Pio::new(0x41);
pub static mut CHAN2: Pio<u8> = Pio::new(0x42);
pub static mut COMMAND: Pio<u8> = Pio::new(0x43);

static SELECT_CHAN0: u8 = 0;
static LOHI: u8 = 0x30;

static CHAN0_DIVISOR: u16 = 2685;

pub unsafe fn init() {
    COMMAND.write(SELECT_CHAN0 | LOHI | 5);
    CHAN0.write((CHAN0_DIVISOR & 0xFF) as u8);
    CHAN0.write((CHAN0_DIVISOR >> 8) as u8);
}
