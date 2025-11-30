use alloc::boxed::Box;
use spin::Mutex;

use crate::{
    arch::device::irqchip::ic_for_chip,
    devices::{serial::SerialKind, uart_16550, uart_pl011},
    dtb::{
        diag_uart_range, get_interrupt,
        irqchip::{register_irq, InterruptHandler, IRQ_CHIP},
    },
    interrupt::irq::trigger,
    sync::CleanLockToken,
};
use fdt::Fdt;
use syscall::Mmio;

pub static COM1: Mutex<SerialKind> = Mutex::new(SerialKind::NotPresent);

pub struct Com1Irq {}

impl InterruptHandler for Com1Irq {
    fn irq_handler(&mut self, irq: u32, token: &mut CleanLockToken) {
        COM1.lock().receive(token);
        unsafe {
            trigger(irq, token);
        }
    }
}

pub unsafe fn init_early(dtb: &Fdt) {
    unsafe {
        if !matches!(*COM1.lock(), SerialKind::NotPresent) {
            // Hardcoded UART
            return;
        }

        if let Some((phys, size, skip_init, cts, compatible)) = diag_uart_range(dtb) {
            let virt = crate::PHYS_OFFSET + phys;
            let serial_opt = if compatible.contains("arm,pl011") {
                let mut serial_port = uart_pl011::SerialPort::new(virt, cts);
                if !skip_init {
                    serial_port.init(false);
                }
                Some(SerialKind::Pl011(serial_port))
            } else if compatible.contains("ns16550a") || compatible.contains("snps,dw-apb-uart") {
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
    //TODO: what should chip index be?
    let virq = IRQ_CHIP.irq_chip_list.chips[0].ic.irq_to_virq(irq).unwrap();
    info!("serial_port virq = {}", virq);
    register_irq(virq as u32, Box::new(Com1Irq {}));
    IRQ_CHIP.irq_enable(virq as u32);
    COM1.lock().enable_irq();
}