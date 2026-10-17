use crate::{
    arch::{device::irqchip::hlic, time},
    dtb::{global_dtb, Fdt, FdtNode},
};
use fdt::properties::Compatible;

pub mod cpu;
pub(crate) mod irqchip;
pub mod serial;

use crate::arch::device::irqchip::init_clint;

unsafe fn init_intc(cpu: &FdtNode) {
    let intc_node = cpu.children().find("interrupt-controller").unwrap();
    assert_eq!(
        intc_node.property::<Compatible>().unwrap().first(),
        "riscv,cpu-intc"
    );
    // This controller is hardwired into interrupt handler code and has no Mmios
    hlic::init(); // enable interrupts at HLIC level
}

pub unsafe fn init() {
    unsafe {
        let fdt = global_dtb().unwrap().unwrap();

        crate::dtb::irqchip::init(&fdt);

        let cpu = fdt.find_node(format!("/cpus/cpu@{}", 0).as_str()).unwrap();
        init_intc(&cpu);
        init_time(&fdt);
    }
}

fn init_time(fdt: &Fdt) {
    let cpus = fdt.root().cpus();
    let clock_freq = cpus.common_timebase_frequency().unwrap() as usize;
    time::init(clock_freq);
}

pub unsafe fn init_noncore() {
    unsafe {
        let fdt = global_dtb().unwrap().unwrap();

        init_clint(&fdt);
        serial::init(&fdt);
    }
}

pub struct ArchPercpuMisc;

impl ArchPercpuMisc {
    pub const fn default() -> Self {
        Self
    }
}
