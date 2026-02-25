use crate::{dtb::get_mmio_address, sync::CleanLockToken, time};
use core::ptr::read_volatile;

static RTC_DR: usize = 0x000;

pub unsafe fn init(fdt: &fdt::Fdt) {
    if let Some(node) = fdt.find_compatible(&["arm,pl031"]) {
        match node
            .reg()
            .and_then(|mut iter| iter.next())
            .and_then(|region| get_mmio_address(fdt, &node, &region))
        {
            Some(phys) => {
                let mut rtc = Pl031rtc { phys };
                info!("PL031 RTC at {:#x}", rtc.phys);
                let mut token = unsafe { CleanLockToken::new() };
                *time::START.lock(token.token()) = (rtc.time() as u128) * time::NANOS_PER_SEC;
            }
            None => {
                warn!("No PL031 RTC registers");
            }
        }
    } else {
        warn!("No PL031 RTC found");
    }
}

struct Pl031rtc {
    pub phys: usize,
}

impl Pl031rtc {
    unsafe fn read(&self, reg: usize) -> u32 {
        unsafe { read_volatile((crate::PHYS_OFFSET + self.phys + reg) as *const u32) }
    }

    pub fn time(&mut self) -> u64 {
        let seconds = unsafe { self.read(RTC_DR) } as u64;
        seconds
    }
}
