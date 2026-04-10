use alloc::boxed::Box;
use fdt::Fdt;

pub use crate::dtb::serial::COM1;
use crate::{
    dtb::{
        get_interrupt, interrupt_parent,
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

pub unsafe fn init(fdt: &Fdt) -> Option<()> {
    unsafe {
        if let Some(node) = fdt.find_compatible(&["ns16550a", "snps,dw-apb-uart"]) {
            let intr = get_interrupt(fdt, &node, 0).unwrap();
            let interrupt_parent = interrupt_parent(fdt, &node)?;
            let phandle = interrupt_parent.property("phandle")?.as_usize()? as u32;
            let ic_idx = IRQ_CHIP.phandle_to_ic_idx(phandle)?;

            let virq = IRQ_CHIP.irq_chip_list.chips[ic_idx]
                .ic
                .irq_xlate(intr)
                .unwrap();
            info!("serial_port virq = {}", virq);
            register_irq(virq as u32, Box::new(Com1Irq {}));
            IRQ_CHIP.irq_enable(virq as u32);
        }
        // COM1.lock().enable_irq(); // FIXME receive int is enabled by default in 16550. Disable by default?
        Some(())
    }
}
