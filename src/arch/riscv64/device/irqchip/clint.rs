use spin::Mutex;
use syscall::{Io, Mmio};
use crate::context::switch::tick;

#[repr(packed(4))]
#[repr(C)]
struct ClintRegs {
    /// per-hart MSIP registers
    /// bit 0: trigger IPI for the hart
    msip: [Mmio<u32>; 4095], // +0000 -- 3fff
    _rsrv1: u32,
    /// per-hart MTIMECMP registers
    /// timer interrupt trigger threshold
    mtimecmp: [Mmio<u64>; 4095], // +4000 - bff7
    mtime: Mmio<u64>  // current time
}

pub struct Clint {
    regs: &'static mut ClintRegs,
    freq: u64
}

pub static CLINT: Mutex<Option<Clint>> = Mutex::new(None);

impl Clint {
    pub fn new(addr: *mut u8, size: usize, freq: usize) -> Self {
        assert!(size >= core::mem::size_of::<ClintRegs>());
        Self {
            regs: unsafe { (addr as *mut ClintRegs).as_mut().unwrap() },
            freq: freq as u64
        }
    }

    pub fn init(self: &mut Self) {
        (*self.regs).mtimecmp[0].write((*self.regs).mtime.read() + self.freq / 100);
    }

    pub fn timer_irq(self: &mut Self, hart: usize) {
        (*self.regs).mtimecmp[hart].write((*self.regs).mtimecmp[hart].read() + self.freq / 100);
        tick();
    }
}
