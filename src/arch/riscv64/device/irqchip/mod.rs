use self::clint::Clint;
use crate::dtb::irqchip::InterruptController;
use alloc::boxed::Box;
use fdt::Fdt;

pub(crate) mod hlic;
mod plic;

#[path = "clint_sbi.rs"]
mod clint;

// pub mod clint; // actual clint.rs off limits if SBI is present

pub fn new_irqchip(ic_str: &str) -> Option<Box<dyn InterruptController>> {
    if ic_str.contains("riscv,cpu-intc") {
        Some(Box::new(hlic::Hlic::new()))
    } else if ic_str.contains("riscv,plic0") {
        Some(Box::new(plic::Plic::new()))
    } else {
        log::warn!("no driver for interrupt controller {:?}", ic_str);
        None
    }
}

pub unsafe fn init_clint(fdt: &Fdt) {
    let cpus = fdt.find_node("/cpus").unwrap();
    let clock_freq = cpus
        .property("timebase-frequency")
        .unwrap()
        .as_usize()
        .unwrap();

    let clint_node = fdt.find_node("/soc/clint").unwrap();
    assert!(clint_node
        .compatible()
        .unwrap()
        .all()
        .find(|x| ((*x).eq("riscv,clint0")))
        .is_some());

    let clint = Clint::new(clock_freq, &clint_node);
    *clint::CLINT.lock() = Some(clint);
    clint::CLINT.lock().as_mut().unwrap().init(0);
}
