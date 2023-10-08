use core::arch::asm;

use crate::memory::Frame;
use crate::paging::{KernelMapper, PhysicalAddress, Page, PageFlags, VirtualAddress};
use crate::dtb::DTB_BINARY;

pub mod cpu;
pub mod irqchip;
pub mod generic_timer;
pub mod serial;
pub mod rtc;
pub mod uart_pl011;

pub unsafe fn init() {
    println!("IRQCHIP INIT");
    let data = DTB_BINARY.get().unwrap();
    let fdt = fdt::DeviceTree::new(data).unwrap();
    irqchip::init(&fdt);
    println!("GIT INIT");
    generic_timer::init();
}

pub unsafe fn init_noncore() {
    let mut daif: usize = 0;
    asm!("mrs {0}, daif", out(reg) daif);
    println!("daif = 0x{:08x}", daif);
    println!("SERIAL INIT");
    serial::init();
    println!("RTC INIT");
    rtc::init();
}

pub unsafe fn init_ap() {
}

//map physical addr X to virtual addr PHYS_OFFSET + X
pub unsafe fn io_mmap(addr: usize, io_size: usize) {
    let mut mapper = KernelMapper::lock();

    let start_frame = Frame::containing_address(PhysicalAddress::new(addr));
    let end_frame = Frame::containing_address(PhysicalAddress::new(addr + io_size - 1));
    for frame in Frame::range_inclusive(start_frame, end_frame) {
        let page = Page::containing_address(VirtualAddress::new(frame.start_address().data() + crate::PHYS_OFFSET));
        mapper
            .get_mut()
            .expect("failed to access KernelMapper for mapping GIC distributor")
            .map_phys(page.start_address(), frame.start_address(), PageFlags::new().write(true))
            .expect("failed to map GIC distributor")
            .flush();
    }

}
