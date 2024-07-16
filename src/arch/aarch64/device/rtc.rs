use core::ptr::read_volatile;

use crate::{
    memory::Frame,
    paging::{KernelMapper, Page, PageFlags, PhysicalAddress, VirtualAddress},
    time,
};

static RTC_DR: u32 = 0x000;

static mut PL031_RTC: Pl031rtc = Pl031rtc { address: 0 };

pub unsafe fn init() {
    PL031_RTC.init();
    *time::START.lock() = (PL031_RTC.time() as u128) * time::NANOS_PER_SEC;
}

struct Pl031rtc {
    pub address: usize,
}

impl Pl031rtc {
    unsafe fn init(&mut self) {
        let mut mapper = KernelMapper::lock();

        let start_frame = Frame::containing_address(PhysicalAddress::new(0x09010000));
        let end_frame = Frame::containing_address(PhysicalAddress::new(0x09010000 + 0x1000 - 1));

        for frame in Frame::range_inclusive(start_frame, end_frame) {
            let page = Page::containing_address(VirtualAddress::new(
                frame.start_address().data() + crate::PHYS_OFFSET,
            ));
            mapper
                .get_mut()
                .expect("failed to access KernelMapper for mapping RTC")
                .map_phys(
                    page.start_address(),
                    frame.start_address(),
                    PageFlags::new().write(true),
                )
                .expect("failed to map RTC")
                .flush();
        }

        self.address = crate::PHYS_OFFSET + 0x09010000;
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        let val = read_volatile((self.address + reg as usize) as *const u32);
        val
    }

    pub fn time(&mut self) -> u64 {
        let seconds = unsafe { self.read(RTC_DR) } as u64;
        seconds
    }
}
