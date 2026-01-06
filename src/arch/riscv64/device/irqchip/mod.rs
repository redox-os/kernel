use self::clint::Clint;
use crate::dtb::irqchip::InterruptController;
use alloc::boxed::Box;
use fdt::Fdt;

pub(crate) mod hlic;
mod plic;

#[path = "clint_sbi.rs"]
mod clint;

const COMPATIBLE_CLINT: [&str; 2] = ["sifive,clint0", "riscv,clint0"];
const COMPATIBLE_HLIC: [&str; 1] = ["riscv,cpu-intc"];
const COMPATIBLE_PLIC: [&str; 3] = ["riscv,plic0", "sifive,plic-1.0.0", "sifive,fu540-c000-plic"];

// pub mod clint; // actual clint.rs off limits if SBI is present

pub fn new_irqchip(compatible: &str) -> Option<Box<dyn InterruptController>> {
    if COMPATIBLE_HLIC.contains(&compatible) {
        Some(Box::new(hlic::Hlic::new()))
    } else if COMPATIBLE_PLIC.contains(&compatible) {
        Some(Box::new(plic::Plic::new()))
    } else {
        warn!(
            "no driver for interrupt controller compatible with: {:?}",
            compatible
        );
        None
    }
}

pub unsafe fn init_clint(fdt: &Fdt) {
    let cpus = fdt.find_node("/cpus").expect("no /cpus in dtb!");
    let clock_freq = cpus
        .property("timebase-frequency")
        .expect("no timebase-frequency property on /cpus!")
        .as_usize()
        .expect("failed to case timebase-frequency property on /cpus!");

    let clint_node = fdt
        .find_node("/soc/clint")
        .expect("clint not found in dtb!");
    assert!(clint_node
        .compatible()
        .expect("no compatible property found on clint!")
        .all()
        .any(|comp| COMPATIBLE_CLINT.contains(&comp)));

    let clint = Clint::new(clock_freq, &clint_node);
    *clint::CLINT.lock() = Some(clint);
    clint::CLINT
        .lock()
        .as_mut()
        .expect("failed to lock CLINT")
        .init(0);
}
