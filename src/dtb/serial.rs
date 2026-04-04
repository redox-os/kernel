use fdt::Fdt;
use spin::Mutex;
use syscall::Mmio;

use crate::{
    devices::{serial::SerialKind, uart_16550, uart_pl011},
    dtb::diag_uart_range,
    memory::{RmmA, RmmArch},
};

pub static COM1: Mutex<SerialKind> = Mutex::new(SerialKind::NotPresent);

#[cfg_attr(not(dtb), expect(dead_code))]
pub unsafe fn init_early(dtb: &Fdt) {
    unsafe {
        if !matches!(*COM1.lock(), SerialKind::NotPresent) {
            // Hardcoded UART
            return;
        }

        if let Some((phys, size, skip_init, cts, compatible)) = diag_uart_range(dtb) {
            let virt = RmmA::phys_to_virt(phys).data();
            let serial_opt = if compatible.contains("arm,pl011") {
                let mut serial_port = uart_pl011::SerialPort::new(virt, cts);
                if !skip_init {
                    serial_port.init(false);
                }
                Some(SerialKind::Pl011(serial_port))
            } else if compatible.contains("ns16550a") {
                if cfg!(target_arch = "riscv64") {
                    //TODO: get actual register size from device tree
                    let serial_port = uart_16550::SerialPort::<Mmio<u8>>::new(virt);
                    if !skip_init {
                        let _ = serial_port.init();
                    }
                    Some(SerialKind::Ns16550u8(serial_port))
                } else {
                    //TODO: get actual register size from device tree
                    let serial_port = uart_16550::SerialPort::<Mmio<u32>>::new(virt);
                    if !skip_init {
                        let _ = serial_port.init();
                    }
                    Some(SerialKind::Ns16550u32(serial_port))
                }
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
