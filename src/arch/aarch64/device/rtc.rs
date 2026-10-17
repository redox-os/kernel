use crate::{
    dtb::{get_mmio_address, Fdt},
    sync::CleanLockToken,
    time,
};
use core::ptr::read_volatile;

static RTC_DR: usize = 0x000;

pub unsafe fn init(fdt: &Fdt<'_>) {
    if let Some(node) = fdt.all_compatible(&["arm,pl031"]).next() {
        match node
            .reg()
            .and_then(|iter| iter.iter::<usize, usize>().next())
            .and_then(|region| region.ok())
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
