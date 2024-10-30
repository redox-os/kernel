use alloc::boxed::Box;
use spin::Mutex;

use crate::{
    arch::device::irqchip::ic_for_chip,
    device::uart_pl011,
    devices::uart_16550,
    dtb::{
        diag_uart_range,
        irqchip::{register_irq, InterruptHandler, IRQ_CHIP},
    },
    interrupt::irq::trigger,
    scheme::debug::{debug_input, debug_notify},
};
use byteorder::{ByteOrder, BE};
use fdt::Fdt;
use log::{error, info};
use syscall::Mmio;

pub enum SerialKind {
    Ns16550u8(&'static mut uart_16550::SerialPort<Mmio<u8>>),
    Ns16550u32(&'static mut uart_16550::SerialPort<Mmio<u32>>),
    Pl011(uart_pl011::SerialPort),
}

impl SerialKind {
    pub fn enable_irq(&mut self) {
        //TODO: implement for NS16550
        match self {
            Self::Ns16550u8(_) => {}
            Self::Ns16550u32(_) => {}
            Self::Pl011(inner) => inner.enable_irq(),
        }
    }

    pub fn receive(&mut self) {
        //TODO: make PL011 receive work the same way as NS16550
        match self {
            Self::Ns16550u8(inner) => {
                while let Some(c) = inner.receive() {
                    debug_input(c);
                }
                debug_notify();
            }
            Self::Ns16550u32(inner) => {
                while let Some(c) = inner.receive() {
                    debug_input(c);
                }
                debug_notify();
            }
            Self::Pl011(inner) => inner.receive(),
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        match self {
            Self::Ns16550u8(inner) => inner.write(buf),
            Self::Ns16550u32(inner) => inner.write(buf),
            Self::Pl011(inner) => inner.write(buf),
        }
    }
}

pub static COM1: Mutex<Option<SerialKind>> = Mutex::new(None);

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
                serial_port.init();
            }
            Some(SerialKind::Ns16550u32(serial_port))
        } else {
            None
        };
        match serial_opt {
            Some(serial) => {
                info!("UART {:?} at {:#X} size {:#X}", compatible, virt, size);
                *COM1.lock() = Some(serial);
            }
            None => {
                log::warn!(
                    "UART {:?} at {:#X} size {:#X}: no driver found",
                    compatible,
                    virt,
                    size
                );
            }
        }
    }
}

pub unsafe fn init(fdt: &Fdt) {
    //TODO: find actual serial device, not just any PL011
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
