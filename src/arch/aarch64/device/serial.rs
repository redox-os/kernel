use core::sync::atomic::{Ordering};
use spin::Mutex;

use crate::device::uart_pl011::SerialPort;
use crate::init::device_tree;
use crate::memory::Frame;
use crate::paging::mapper::PageFlushAll;
use crate::paging::{ActivePageTable, Page, PageFlags, PhysicalAddress, TableKind, VirtualAddress};

pub static COM1: Mutex<Option<SerialPort>> = Mutex::new(None);

pub unsafe fn init_early(dtb_base: usize, dtb_size: usize) {
    if COM1.lock().is_some() {
        // Hardcoded UART
        return;
    }

    if let Some((phys, size)) = device_tree::diag_uart_range(dtb_base, dtb_size) {
        let virt = crate::KERNEL_DEVMAP_OFFSET + phys;
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
    }
}
