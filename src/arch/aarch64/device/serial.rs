use alloc::boxed::Box;
use spin::Mutex;

use crate::{device::uart_pl011::SerialPort, interrupt::irq::trigger};
use crate::init::device_tree;

use super::irqchip::{register_irq, IRQ_CHIP, InterruptHandler};

pub static COM1: Mutex<Option<SerialPort>> = Mutex::new(None);

pub struct Com1Irq {
}

impl InterruptHandler for Com1Irq {
    fn irq_handler(&mut self, irq: u32) {
        if let Some(ref mut serial_port) = *COM1.lock() {
            serial_port.receive();
        };
        unsafe { trigger(irq); }
    }
}


pub unsafe fn init_early(dtb_base: usize, dtb_size: usize) {
    if COM1.lock().is_some() {
        // Hardcoded UART
        return;
    }

    if let Some((phys, size)) = device_tree::diag_uart_range(dtb_base, dtb_size) {
        let virt = crate::PHYS_OFFSET + phys;
        {
            let mut serial_port = SerialPort::new(virt);
            serial_port.init(false);
            *COM1.lock() = Some(serial_port);
        }
        println!("UART at {:X}", virt);
    }
}

pub unsafe fn init() {
    if let Some(ref mut serial_port) = *COM1.lock() {
        serial_port.init(true);
        register_irq(33, Box::new(Com1Irq {}));
        // Enable interrupt at GIC distributor
        unsafe { IRQ_CHIP.irq_enable(33); }
    }
}
