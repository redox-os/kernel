use crate::dtb::irqchip::InterruptController;
use alloc::boxed::Box;

mod gic;
mod gicv3;
mod irq_bcm2835;
mod irq_bcm2836;

pub fn new_irqchip(ic_str: &str) -> Option<Box<dyn InterruptController>> {
    if ic_str.contains("arm,gic-v3") {
        Some(Box::new(gicv3::GicV3::new()))
    } else if ic_str.contains("arm,cortex-a15-gic") {
        Some(Box::new(gic::GenericInterruptController::new()))
    } else if ic_str.contains("brcm,bcm2836-l1-intc") {
        Some(Box::new(irq_bcm2836::Bcm2836ArmInterruptController::new()))
    } else if ic_str.contains("brcm,bcm2836-armctrl-ic") {
        Some(Box::new(irq_bcm2835::Bcm2835ArmInterruptController::new()))
    } else {
        log::warn!("no driver for interrupt controller {:?}", ic_str);
        None
    }
}
