use crate::dtb::irqchip::{InterruptController, IRQ_CHIP};
use alloc::boxed::Box;
use fdt::{node::FdtNode, Fdt};

pub(crate) mod gic;
pub(crate) mod gicv3;
mod irq_bcm2835;
mod irq_bcm2836;
mod null;

pub(crate) fn new_irqchip(ic_str: &str) -> Option<Box<dyn InterruptController>> {
    if ic_str.contains("arm,gic-v3") {
        Some(Box::new(gicv3::GicV3::new()))
    } else if ic_str.contains("arm,cortex-a15-gic") || ic_str.contains("arm,gic-400") {
        Some(Box::new(gic::GenericInterruptController::new()))
    } else if ic_str.contains("brcm,bcm2836-l1-intc") {
        Some(Box::new(irq_bcm2836::Bcm2836ArmInterruptController::new()))
    } else if ic_str.contains("brcm,bcm2836-armctrl-ic") {
        Some(Box::new(irq_bcm2835::Bcm2835ArmInterruptController::new()))
    } else {
        log::warn!("no driver for interrupt controller {:?}", ic_str);
        //TODO: return None and handle it properly
        Some(Box::new(null::Null))
    }
}

pub(crate) fn ic_for_chip(fdt: &Fdt, node: &FdtNode) -> Option<usize> {
    if let Some(_) = node.property("interrupts-extended") {
        log::error!("multi-parented device not supported");
        None
    } else if let Some(irqc_phandle) = node
        .property("interrupt-parent")
        .or(fdt.root().property("interrupt-parent"))
        .and_then(|f| f.as_usize())
    {
        unsafe { IRQ_CHIP.phandle_to_ic_idx(irqc_phandle as u32) }
    } else {
        log::error!("no irq parent found");
        None
    }
}
