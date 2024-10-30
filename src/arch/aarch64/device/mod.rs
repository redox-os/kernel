use crate::info;
use core::sync::atomic::{AtomicUsize, Ordering};
use fdt::Fdt;

pub mod cpu;
pub mod generic_timer;
pub mod irqchip;
pub mod rtc;
pub mod serial;
pub mod uart_pl011;

use crate::dtb::irqchip::IRQ_CHIP;
use irqchip::ic_for_chip;

pub static ROOT_IC_IDX: AtomicUsize = AtomicUsize::new(0);

unsafe fn init_root_ic(fdt: &Fdt) {
    let root_irqc_phandle = fdt
        .root()
        .property("interrupt-parent")
        .unwrap()
        .as_usize()
        .unwrap();
    let ic_idx = IRQ_CHIP
        .phandle_to_ic_idx(root_irqc_phandle as u32)
        .unwrap();
    ROOT_IC_IDX.store(ic_idx, Ordering::Relaxed);
}

pub unsafe fn init_devicetree(fdt: &Fdt) {
    info!("IRQCHIP INIT");
    crate::dtb::irqchip::init(&fdt);
    init_root_ic(&fdt);
    info!("GIT INIT");
    generic_timer::init(fdt);
    info!("SERIAL INIT");
    serial::init(fdt);
    info!("RTC INIT");
    rtc::init(fdt);
}

#[derive(Default)]
pub struct ArchPercpuMisc;
