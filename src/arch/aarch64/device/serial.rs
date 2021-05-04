use core::sync::atomic::{Ordering};
use spin::Mutex;

use crate::device::uart_pl011::SerialPort;
use crate::init::device_tree;
use crate::memory::Frame;
use crate::paging::mapper::{MapperFlushAll, MapperType};
use crate::paging::{ActivePageTable, Page, PageTableType, PhysicalAddress, VirtualAddress};
use crate::paging::entry::EntryFlags;

pub static COM1: Mutex<Option<SerialPort>> = Mutex::new(None);

pub unsafe fn init() {
    if let Some(ref mut serial_port) = *COM1.lock() {
        return;
    }
    let (base, size) = device_tree::diag_uart_range(crate::KERNEL_DTB_OFFSET, crate::KERNEL_DTB_MAX_SIZE).unwrap();

    let mut active_ktable = unsafe { ActivePageTable::new(PageTableType::Kernel) };
    let mut flush_all = MapperFlushAll::new();

    let start_frame = Frame::containing_address(PhysicalAddress::new(base));
    let end_frame = Frame::containing_address(PhysicalAddress::new(base + size - 1));
    for frame in Frame::range_inclusive(start_frame, end_frame) {
        let page = Page::containing_address(VirtualAddress::new(frame.start_address().data() + crate::KERNEL_DEVMAP_OFFSET));
        let result = active_ktable.map_to(page, frame, EntryFlags::PRESENT | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE);
        flush_all.consume(result);
    };
    flush_all.flush(&mut active_ktable);

    let start_frame = Frame::containing_address(PhysicalAddress::new(base));
    let vaddr = start_frame.start_address().data() + crate::KERNEL_DEVMAP_OFFSET;

    *COM1.lock() = Some(SerialPort::new(vaddr));
    if let Some(ref mut serial_port) = *COM1.lock() {
        serial_port.init(true);
    }
}
