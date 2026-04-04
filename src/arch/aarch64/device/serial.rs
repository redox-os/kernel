use alloc::boxed::Box;
use fdt::Fdt;

pub use crate::dtb::serial::COM1;
use crate::{
    arch::device::irqchip::ic_for_chip,
    dtb::{
        get_interrupt,
        irqchip::{register_irq, InterruptHandler, IRQ_CHIP},
    },
    scheme::irq::irq_trigger,
    sync::CleanLockToken,
};

pub struct Com1Irq {}

impl InterruptHandler for Com1Irq {
    fn irq_handler(&mut self, irq: u32, token: &mut CleanLockToken) {
        COM1.lock().receive(token);
        unsafe {
            // FIXME add_irq accepts a u8 as irq number
            // PercpuBlock::current().stats.add_irq(irq);
            irq_trigger(irq.try_into().unwrap(), token);
            IRQ_CHIP.irq_eoi(irq);
        }
    }
}

pub unsafe fn init(fdt: &Fdt) {
    unsafe {
        //TODO: find actual serial device, not just any PL011
        if let Some(node) = fdt.find_compatible(&["arm,pl011"]) {
            let irq = get_interrupt(fdt, &node, 0).unwrap();
            if let Some(ic_idx) = ic_for_chip(&fdt, &node) {
                let virq = IRQ_CHIP.irq_chip_list.chips[ic_idx]
                    .ic
                    .irq_xlate(irq)
                    .unwrap();
                info!("serial_port virq = {}", virq);
                register_irq(virq as u32, Box::new(Com1Irq {}));
                IRQ_CHIP.irq_enable(virq as u32);
            } else {
                error!("serial port irq parent not found");
            }
        }
        COM1.lock().enable_irq();
    }
}

pub unsafe fn init_acpi(irq: u32) {
    unsafe {
        //TODO: what should chip index be?
        let virq = IRQ_CHIP.irq_chip_list.chips[0].ic.irq_to_virq(irq).unwrap();
        info!("serial_port virq = {}", virq);
        register_irq(virq as u32, Box::new(Com1Irq {}));
        IRQ_CHIP.irq_enable(virq as u32);
        COM1.lock().enable_irq();
    }
}
