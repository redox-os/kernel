use alloc::boxed::Box;
use byteorder::{ByteOrder, BE};
use fdt::Fdt;
use log::info;
use spin::Mutex;
use syscall::Mmio;

use crate::{
    devices::uart_16550,
    dtb::{
        diag_uart_range,
        irqchip::{register_irq, InterruptHandler, IRQ_CHIP},
    },
    scheme::{
        debug::{debug_input, debug_notify},
        irq::irq_trigger,
    },
};

pub struct SerialPort {
    inner: &'static mut uart_16550::SerialPort<Mmio<u8>>,
}
impl SerialPort {
    pub fn write(&mut self, buf: &[u8]) {
        self.inner.write(buf)
    }
    pub fn receive(&mut self) {
        while let Some(c) = self.inner.receive() {
            debug_input(c);
        }
        debug_notify();
    }
}

pub static COM1: Mutex<Option<SerialPort>> = Mutex::new(None);

pub struct Com1Irq {}

impl InterruptHandler for Com1Irq {
    fn irq_handler(&mut self, irq: u32) {
        if let Some(ref mut serial_port) = *COM1.lock() {
            serial_port.receive();
        };
        unsafe {
            irq_trigger(irq as u8);
            IRQ_CHIP.irq_eoi(irq);
        }
    }
}

pub unsafe fn init_early(dtb: &Fdt) {
    if COM1.lock().is_some() {
        // Hardcoded UART
        return;
    }

    if let Some((phys, _, _, _, compatible)) = diag_uart_range(dtb) {
        let virt = crate::PHYS_OFFSET + phys;
        let port = if compatible == "ns16550a" {
            let serial_port = uart_16550::SerialPort::<Mmio<u8>>::new(virt);
            serial_port.init();
            Some(SerialPort { inner: serial_port })
        } else {
            None
        };
        match port {
            Some(port) => {
                *COM1.lock() = Some(port);
            }
            None => {}
        }
    }
}

pub unsafe fn init(fdt: &Fdt) -> Option<()> {
    if let Some(node) = fdt.find_compatible(&["ns16550a"]) {
        let interrupts = node.property("interrupts").unwrap();
        let mut intr_data: [u32; 3] = [0, 0, 0];
        for (idx, chunk) in interrupts.value.chunks(4).enumerate() {
            if idx >= intr_data.len() {
                break;
            }
            let val = BE::read_u32(chunk);
            intr_data[idx] = val;
        }

        let interrupt_parent = node.interrupt_parent()?;
        let phandle = interrupt_parent.property("phandle")?.as_usize()? as u32;
        let ic_idx = IRQ_CHIP.phandle_to_ic_idx(phandle)?;

        let virq = IRQ_CHIP.irq_chip_list.chips[ic_idx]
            .ic
            .irq_xlate(&intr_data)
            .unwrap();
        info!("serial_port virq = {}", virq);
        register_irq(virq as u32, Box::new(Com1Irq {}));
        IRQ_CHIP.irq_enable(virq as u32);
    }
    if let Some(ref mut _serial_port) = *COM1.lock() {
        // serial_port.enable_irq(); // FIXME receive int is enabled by default in 16550. Disable by default?
    }
    Some(())
}
