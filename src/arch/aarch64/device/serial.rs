use core::sync::atomic::{Ordering};
use spin::Mutex;

use crate::device::uart_pl011::SerialPort;
use crate::init::device_tree;
use crate::memory::Frame;
use crate::paging::mapper::PageFlushAll;
use crate::paging::{ActivePageTable, Page, PageFlags, PhysicalAddress, TableKind, VirtualAddress};

pub static COM1: Mutex<Option<SerialPort>> = Mutex::new(None);

pub unsafe fn init() {
    if COM1.lock().is_none() {
        let (base, size) = device_tree::diag_uart_range(crate::KERNEL_DTB_OFFSET, crate::KERNEL_DTB_MAX_SIZE).unwrap();

        let mut active_ktable = unsafe { ActivePageTable::new(TableKind::Kernel) };
        let mut flush_all = PageFlushAll::new();

        let start_frame = Frame::containing_address(PhysicalAddress::new(base));
        let end_frame = Frame::containing_address(PhysicalAddress::new(base + size - 1));
        for frame in Frame::range_inclusive(start_frame, end_frame) {
            let page = Page::containing_address(VirtualAddress::new(frame.start_address().data() + crate::KERNEL_DEVMAP_OFFSET));
            let result = active_ktable.map_to(page, frame, PageFlags::new().write(true));
            flush_all.consume(result);
        };
        flush_all.flush();

        let start_frame = Frame::containing_address(PhysicalAddress::new(base));
        let vaddr = start_frame.start_address().data() + crate::KERNEL_DEVMAP_OFFSET;

        *COM1.lock() = Some(SerialPort::new(vaddr));
    }

    if let Some(ref mut serial_port) = *COM1.lock() {
        serial_port.init(true);
    }
}
