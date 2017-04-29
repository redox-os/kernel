use syscall::io::{Io, Pio};
use time;

pub fn init() {
    let mut rtc = Rtc::new();
    time::START.lock().0 = rtc.time();
}

fn cvt_bcd(value: usize) -> usize {
    (value & 0xF) + ((value / 16) * 10)
}

/// RTC
pub struct Rtc {
    addr: Pio<u8>,
    data: Pio<u8>,
}

impl Rtc {
    /// Create new empty RTC
    pub fn new() -> Self {
        return Rtc {
                   addr: Pio::<u8>::new(0x70),
                   data: Pio::<u8>::new(0x71),
               };
    }

    /// Read
    unsafe fn read(&mut self, reg: u8) -> u8 {
        self.addr.write(reg);
        return self.data.read();
    }

    /// Wait
    unsafe fn wait(&mut self) {
        while self.read(0xA) & 0x80 != 0x80 {}
        while self.read(0xA) & 0x80 == 0x80 {}
    }

    /// Get time
    pub fn time(&mut self) -> u64 {
        let mut second;
        let mut minute;
        let mut hour;
        let mut day;
        let mut month;
        let mut year;
        let mut century;
        let register_b;

        /*let century_register = if let Some(ref fadt) = acpi::ACPI_TABLE.lock().fadt {
            Some(fadt.century)
        } else {
            None
        };*/

        unsafe {
            self.wait();
            second = self.read(0) as usize;
            minute = self.read(2) as usize;
            hour = self.read(4) as usize;
            day = self.read(7) as usize;
            month = self.read(8) as usize;
            year = self.read(9) as usize;
            century = /* TODO: Fix invalid value from VirtualBox
            if let Some(century_reg) = century_register {
                self.read(century_reg) as usize
            } else */ {
                20 as usize
            };
            register_b = self.read(0xB);
        }

        if register_b & 4 != 4 {
            second = cvt_bcd(second);
            minute = cvt_bcd(minute);
            hour = cvt_bcd(hour & 0x7F) | (hour & 0x80);
            day = cvt_bcd(day);
            month = cvt_bcd(month);
            year = cvt_bcd(year);
            century = /* TODO: Fix invalid value from VirtualBox
            if century_register.is_some() {
                cvt_bcd(century)
            } else */ {
                century
            };
        }

        if register_b & 2 != 2 || hour & 0x80 == 0x80 {
            hour = ((hour & 0x7F) + 12) % 24;
        }

        year += century * 100;

        // Unix time from clock
        let mut secs: u64 = (year as u64 - 1970) * 31536000;

        let mut leap_days = (year as u64 - 1972) / 4 + 1;
        if year % 4 == 0 {
            if month <= 2 {
                leap_days -= 1;
            }
        }
        secs += leap_days * 86400;

        match month {
            2 => secs += 2678400,
            3 => secs += 5097600,
            4 => secs += 7776000,
            5 => secs += 10368000,
            6 => secs += 13046400,
            7 => secs += 15638400,
            8 => secs += 18316800,
            9 => secs += 20995200,
            10 => secs += 23587200,
            11 => secs += 26265600,
            12 => secs += 28857600,
            _ => (),
        }

        secs += (day as u64 - 1) * 86400;
        secs += hour as u64 * 3600;
        secs += minute as u64 * 60;
        secs += second as u64;

        secs
    }
}
