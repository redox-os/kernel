use alloc::boxed::Box;
use spin::Mutex;

use crate::{
    device::uart_pl011::SerialPort,
    init::device_tree,
    interrupt::irq::trigger,
    log::{debug, info},
};

use super::irqchip::{register_irq, InterruptHandler, IRQ_CHIP};
use crate::{dtb::DTB_BINARY, init::device_tree::find_compatible_node};
use alloc::vec::Vec;
use byteorder::{ByteOrder, BE};

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

pub unsafe fn init_early(dtb_base: usize, dtb_size: usize) {
    if COM1.lock().is_some() {
        // Hardcoded UART
        return;
    }

    if let Some((phys, size, skip_init, cts)) = device_tree::diag_uart_range(dtb_base, dtb_size) {
        let virt = crate::PHYS_OFFSET + phys;
        {
            let mut serial_port = SerialPort::new(virt, skip_init, cts);
            serial_port.init(false);
            *COM1.lock() = Some(serial_port);
        }
        info!("UART at {:X}", virt);
    }
}

pub unsafe fn init() {
    let data = DTB_BINARY.get().unwrap();
    let fdt = fdt::DeviceTree::new(data).unwrap();
    if let Some(node) = find_compatible_node(&fdt, "arm,pl011") {
        let interrupts = node
            .properties()
            .find(|p| p.name.contains("interrupts"))
            .unwrap();
        let mut intr_data = Vec::new();
        for chunk in interrupts.data.chunks(4) {
            let val = BE::read_u32(chunk);
            intr_data.push(val);
        }
        let mut ic_idx = IRQ_CHIP.irq_chip_list.root_idx;
        if let Some(interrupt_parent) = node
            .properties()
            .find(|p| p.name.contains("interrupt-parent"))
        {
            let phandle = BE::read_u32(interrupt_parent.data);
            let mut i = 0;
            while i < IRQ_CHIP.irq_chip_list.chips.len() {
                let item = &IRQ_CHIP.irq_chip_list.chips[i];
                if item.phandle == phandle {
                    ic_idx = i;
                    break;
                }
                i += 1;
            }
        }
        let virq = IRQ_CHIP.irq_chip_list.chips[ic_idx]
            .ic
            .irq_xlate(&intr_data, 0)
            .unwrap();
        info!("serial_port virq = {}", virq);
        register_irq(virq as u32, Box::new(Com1Irq {}));
        IRQ_CHIP.irq_enable(virq as u32);
    }
    if let Some(ref mut serial_port) = *COM1.lock() {
        serial_port.enable_irq();
    }
}
