use spin::Mutex;
use syscall::io::{Io, Pio};

pub static SYSTEM76_EC: Mutex<Option<System76Ec>> = Mutex::new(None);

pub fn init() {
    *SYSTEM76_EC.lock() = System76Ec::new();
}

pub struct System76Ec {
    base: u16,
}

impl System76Ec {
    pub fn new() -> Option<Self> {
        let mut system76_ec = Self {
            base: 0x0E00,
        };
        if system76_ec.probe() {
            Some(system76_ec)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn read(&mut self, addr: u8) -> u8 {
        Pio::<u8>::new(self.base + addr as u16).read()
    }

    #[inline(always)]
    pub fn write(&mut self, addr: u8, data: u8) {
        Pio::<u8>::new(self.base + addr as u16).write(data)
    }

    pub fn probe(&mut self) -> bool {
        // Send probe command
        self.write(0, 1);

        // Wait for response
        let mut timeout = 1_000_000;
        while timeout > 0 {
            if self.read(0) == 0 {
                break;
            }
            timeout -= 1;
        }
        if timeout == 0 {
            return false;
        }

        // Return false on command error
        if self.read(1) != 0 {
            return false;
        }

        // Must receive 0x76, 0xEC as signature
        self.read(2) == 0x76 && self.read(3) == 0xEC
    }

    pub fn flush(&mut self) {
        // Send command
        self.write(0, 4);

        // TODO: timeout
        while self.read(0) != 0 {}

        // Clear length
        self.write(3, 0);
    }

    pub fn print(&mut self, byte: u8) {
        // Read length
        let len = self.read(3);
        // Write data at offset
        self.write(len + 4, byte);
        // Update length
        self.write(3, len + 1);

        // If we hit the end of the buffer, or were given a newline, flush
        if byte == b'\n' || len >= 128 {
            self.flush();
        }
    }

    pub fn print_slice(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.print(byte);
        }
    }
}
