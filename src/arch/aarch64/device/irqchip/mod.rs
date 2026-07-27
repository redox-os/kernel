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
        warn!("no driver for interrupt controller {:?}", ic_str);
        //TODO: return None and handle it properly
        Some(Box::new(null::Null))
    }
}

pub(crate) fn ic_for_chip(fdt: &Fdt, node: &FdtNode) -> Option<usize> {
    if let Some(_) = node.property("interrupts-extended") {
        error!("multi-parented device not supported");
        None
    } else if let Some(irqc_phandle) = node
        .property("interrupt-parent")
        .or(fdt.root().property("interrupt-parent"))
        .and_then(|f| f.as_usize())
    {
        unsafe { IRQ_CHIP.phandle_to_ic_idx(irqc_phandle as u32) }
    } else {
        error!("no irq parent found");
        None
    }
}

pub(crate) fn init_ap() -> syscall::Result<()> {
    if gic::active() {
        gic::init_current_cpu()?;
        gic::current_cpu_target_mask()
            .map(|_| ())
            .ok_or_else(|| syscall::Error::new(syscall::error::EINVAL))
    } else {
        Err(syscall::Error::new(syscall::error::ENODEV))
    }
}

pub(crate) fn cpu_capacity() -> Option<usize> {
    gic::cpu_capacity()
}

pub(crate) fn current_cpu_target_mask() -> Option<u8> {
    gic::active().then(gic::current_cpu_target_mask).flatten()
}

pub(crate) fn enable_local_irq(hwirq: u32) -> syscall::Result<()> {
    if gic::active() {
        gic::enable_local_irq(hwirq)
    } else {
        Err(syscall::Error::new(syscall::error::ENODEV))
    }
}

pub(crate) fn acknowledge_root() -> (u32, u32, Option<usize>) {
    if let Some(raw) = gic::acknowledge_local() {
        let hwirq = raw & 0x3ff;
        return (raw, hwirq, gic::virq_for(raw));
    }

    unsafe {
        let ic = &mut IRQ_CHIP.irq_chip_list.chips
            [super::ROOT_IC_IDX.load(core::sync::atomic::Ordering::Acquire)]
        .ic;
        let raw = ic.irq_ack();
        (raw, raw, ic.irq_to_virq(raw))
    }
}

pub(crate) fn end_root(raw_iar: u32) {
    if gic::end_local(raw_iar) {
        return;
    }
    unsafe {
        IRQ_CHIP.irq_chip_list.chips
            [super::ROOT_IC_IDX.load(core::sync::atomic::Ordering::Acquire)]
        .ic
        .irq_eoi(raw_iar);
    }
}

pub(crate) fn send_sgi(sgi: u8, target_mask: Option<u8>) -> syscall::Result<()> {
    gic::send_sgi(sgi, target_mask)
}
