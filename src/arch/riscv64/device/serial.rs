use alloc::boxed::Box;
use fdt::Fdt;
use spin::Mutex;
use syscall::Mmio;

use crate::{
    devices::{serial::SerialKind, uart_16550},
    dtb::{
        diag_uart_range, get_interrupt, interrupt_parent,
        irqchip::{register_irq, InterruptHandler, IRQ_CHIP},
    },
    scheme::irq::irq_trigger,
    sync::CleanLockToken,
};

pub static COM1: Mutex<SerialKind> = Mutex::new(SerialKind::NotPresent);

pub struct Com1Irq {}

impl InterruptHandler for Com1Irq {
    fn irq_handler(&mut self, irq: u32, token: &mut CleanLockToken) {
        COM1.lock().receive(token);
        unsafe {
            irq_trigger(irq as u8, token);
            IRQ_CHIP.irq_eoi(irq);
        }
    }
}

pub unsafe fn init_early(dtb: &Fdt) {
    unsafe {
        if !matches!(*COM1.lock(), SerialKind::NotPresent) {
            // Hardcoded UART
            return;
        }

        if let Some((phys, size, skip_init, _cts, compatible)) = diag_uart_range(dtb) {
            let virt = crate::PHYS_OFFSET + phys;
            let serial_opt = if compatible.contains("ns16550a") {
                //TODO: get actual register size from device tree
                let serial_port = uart_16550::SerialPort::<Mmio<u8>>::new(virt);
                if !skip_init {
                    let _ = serial_port.init();
                }
                Some(SerialKind::Ns16550u8(serial_port))
            } else if compatible.contains("snps,dw-apb-uart") {
                //TODO: get actual register size from device tree
                let serial_port = uart_16550::SerialPort::<Mmio<u32>>::new(virt);
                if !skip_init {
                    let _ = serial_port.init();
                }
                Some(SerialKind::Ns16550u32(serial_port))
            } else {
                None
            };
            match serial_opt {
                Some(serial) => {
                    *COM1.lock() = serial;
                    info!("UART {:?} at {:#X} size {:#X}", compatible, virt, size);
                }
                None => {
                    warn!(
                        "UART {:?} at {:#X} size {:#X}: no driver found",
                        compatible, virt, size
                    );
                }
            }
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
