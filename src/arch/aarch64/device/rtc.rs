use core::intrinsics::{volatile_load, volatile_store};

use crate::memory::Frame;
use crate::paging::{ActivePageTable, PhysicalAddress, Page, PageFlags, TableKind, VirtualAddress};
use crate::time;

static RTC_DR: u32 = 0x000;
static RTC_MR: u32 = 0x004;
static RTC_LR: u32 = 0x008;
static RTC_CR: u32 = 0x00c;
static RTC_IMSC: u32 = 0x010;
static RTC_RIS: u32 = 0x014;
static RTC_MIS: u32 = 0x018;
static RTC_ICR: u32 = 0x01c;

static mut PL031_RTC: Pl031rtc = Pl031rtc {
    address: 0,
};

pub unsafe fn init() {
    PL031_RTC.init();
    time::START.lock().0 = PL031_RTC.time();
}

struct Pl031rtc {
    pub address: usize,
}

impl Pl031rtc {
    unsafe fn init(&mut self) {
        let mut active_table = ActivePageTable::new(TableKind::Kernel);

        let start_frame = Frame::containing_address(PhysicalAddress::new(0x09010000));
        let end_frame = Frame::containing_address(PhysicalAddress::new(0x09010000 + 0x1000 - 1));

        for frame in Frame::range_inclusive(start_frame, end_frame) {
            let page = Page::containing_address(VirtualAddress::new(frame.start_address().data() + crate::KERNEL_DEVMAP_OFFSET));
            let result = active_table.map_to(page, frame, PageFlags::new().write(true));
            result.flush();
        }

        self.address = crate::KERNEL_DEVMAP_OFFSET + 0x09010000;
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        let val = volatile_load((self.address + reg as usize) as *const u32);
        val
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        volatile_store((self.address + reg as usize) as *mut u32, value);
    }

    pub fn time(&mut self) -> u64 {
        let seconds = unsafe { self.read(RTC_DR) } as u64;
        seconds
    }
}
