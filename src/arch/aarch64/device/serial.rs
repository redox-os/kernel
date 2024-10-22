use alloc::boxed::Box;
use spin::Mutex;

use crate::{device::uart_pl011::SerialPort, interrupt::irq::trigger};

use crate::{
    arch::device::irqchip::ic_for_chip,
    dtb::{
        diag_uart_range,
        irqchip::{register_irq, InterruptHandler, IRQ_CHIP},
    },
};
use byteorder::{ByteOrder, BE};
use fdt::Fdt;
use log::{error, info};

pub static COM1: Mutex<Option<SerialPort>> = Mutex::new(None);

pub struct Com1Irq {}

impl InterruptHandler for Com1Irq {
    fn irq_handler(&mut self, irq: u32) {
        if let Some(ref mut serial_port) = *COM1.lock() {
            serial_port.receive();
        };
        unsafe {
            trigger(irq);
        }
    }
}

pub unsafe fn init_early(dtb: &Fdt) {
    if COM1.lock().is_some() {
        // Hardcoded UART
        return;
    }

    if let Some((phys, _size, skip_init, cts, _)) = diag_uart_range(dtb) {
        let virt = crate::PHYS_OFFSET + phys;
        {
            let mut serial_port = SerialPort::new(virt, skip_init, cts);
            serial_port.init(false);
            *COM1.lock() = Some(serial_port);
        }
        info!("UART at {:X}", virt);
    }
}

pub unsafe fn init(fdt: &Fdt) {
    if let Some(node) = fdt.find_compatible(&["arm,pl011"]) {
        let interrupts = node.property("interrupts").unwrap();
        let irq = interrupts
            .value
            .array_chunks::<4>()
            .map(|f| BE::read_u32(f))
            .next_chunk::<3>()
            .unwrap();
        if let Some(ic_idx) = ic_for_chip(&fdt, &node) {
            let virq = IRQ_CHIP.irq_chip_list.chips[ic_idx]
                .ic
                .irq_xlate(&irq)
                .unwrap();
            info!("serial_port virq = {}", virq);
            register_irq(virq as u32, Box::new(Com1Irq {}));
            IRQ_CHIP.irq_enable(virq as u32);
        } else {
            error!("serial port irq parent not found");
        }
    }
    if let Some(ref mut serial_port) = *COM1.lock() {
        serial_port.enable_irq();
    }
}
