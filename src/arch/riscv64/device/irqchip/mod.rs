use self::clint::Clint;
use crate::dtb::{irqchip::InterruptController, Fdt};
use alloc::boxed::Box;
use fdt::properties::Compatible;

pub(crate) mod hlic;
mod plic;

#[path = "clint_sbi.rs"]
mod clint;

// pub mod clint; // actual clint.rs off limits if SBI is present

pub fn new_irqchip(ic_str: &str) -> Option<Box<dyn InterruptController>> {
    if ic_str.contains("riscv,cpu-intc") {
        Some(Box::new(hlic::Hlic::new()))
    } else if ic_str.contains("riscv,plic0") || ic_str.contains("sifive,plic-1.0.0") {
        Some(Box::new(plic::Plic::new()))
    } else {
        warn!("no driver for interrupt controller {:?}", ic_str);
        None
    }
}

pub unsafe fn init_clint(fdt: &Fdt) {
    let cpus = fdt.root().cpus();
    let clock_freq = cpus.common_timebase_frequency().unwrap() as usize;

    let clint_node = fdt.find_node("/soc/clint").unwrap();
    assert!(clint_node
        .property::<Compatible>()
        .unwrap()
        .all()
        .find(|x| (*x).eq("riscv,clint0"))
        .is_some());

    let clint = Clint::new(clock_freq, &clint_node);
    *clint::CLINT.lock() = Some(clint);
    clint::CLINT.lock().as_mut().unwrap().init(0);
}
