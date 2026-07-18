use alloc::boxed::Box;
use fdt::Fdt;

pub use crate::dtb::serial::COM1;
use crate::{
    arch::device::irqchip::ic_for_chip,
    dtb::{
        diag_uart_node, get_interrupt,
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
        let Some(node) = diag_uart_node(fdt) else {
            error!("diagnostic serial port not found in devicetree");
            return;
        };
        let Some(irq) = get_interrupt(fdt, &node, 0) else {
            error!("diagnostic serial port interrupt not found");
            return;
        };
        let Some(ic_idx) = ic_for_chip(&fdt, &node) else {
            error!("serial port irq parent not found");
            return;
        };

        if let Err(err) = IRQ_CHIP.irq_chip_list.chips[ic_idx].ic.irq_configure(irq) {
            error!("serial port interrupt configuration failed: {:?}", err);
            return;
        }

        let Ok(virq) = IRQ_CHIP.irq_chip_list.chips[ic_idx].ic.irq_xlate(irq) else {
            error!("serial port interrupt translation failed");
            return;
        };
        if COM1.lock().init_full().is_err() {
            error!("failed to initialize diagnostic serial port");
            return;
        }

        info!("serial_port virq = {}", virq);
        register_irq(virq as u32, Box::new(Com1Irq {}));
        COM1.lock().enable_irq();
        IRQ_CHIP.irq_enable(virq as u32);
    }
}

pub unsafe fn init_acpi(irq: u32) {
    unsafe {
        //TODO: what should chip index be?
        let virq = IRQ_CHIP.irq_chip_list.chips[0].ic.irq_to_virq(irq).unwrap();
        info!("serial_port virq = {}", virq);
        register_irq(virq as u32, Box::new(Com1Irq {}));
        COM1.lock().enable_irq();
        IRQ_CHIP.irq_enable(virq as u32);
    }
}
