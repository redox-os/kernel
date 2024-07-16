use crate::{dtb::DTB_BINARY, info};

pub mod cpu;
pub mod generic_timer;
pub mod irqchip;
pub mod rtc;
pub mod serial;
pub mod uart_pl011;

pub unsafe fn init() {
    info!("IRQCHIP INIT");
    let data = DTB_BINARY.get().unwrap();
    let fdt = fdt::DeviceTree::new(data).unwrap();
    irqchip::init(&fdt);
    info!("GIT INIT");
    generic_timer::init();
}

pub unsafe fn init_noncore() {
    info!("SERIAL INIT");
    serial::init();
    info!("RTC INIT");
    rtc::init();
}

#[derive(Default)]
pub struct ArchPercpuMisc;
