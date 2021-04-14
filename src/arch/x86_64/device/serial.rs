use crate::devices::uart_16550::SerialPort;
#[cfg(feature = "lpss_debug")]
use crate::syscall::io::Mmio;
use crate::syscall::io::Pio;
use spin::Mutex;

pub static COM1: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x3F8));
pub static COM2: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x2F8));
pub static COM3: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x3E8));
pub static COM4: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x2E8));

#[cfg(feature = "lpss_debug")]
pub static LPSS: Mutex<Option<&'static mut SerialPort<Mmio<u32>>>> = Mutex::new(None);

pub unsafe fn init() {
    COM1.lock().init();
    COM2.lock().init();

    #[cfg(feature = "lpss_debug")]
    {
        // TODO: Make this configurable
        let address = crate::PHYS_OFFSET + 0xFE032000;

        {
            use crate::paging::{ActivePageTable, Page, VirtualAddress, entry::EntryFlags};
            use crate::memory::{Frame, PhysicalAddress};

            let mut active_table = ActivePageTable::new();
            let page = Page::containing_address(VirtualAddress::new(address));
            let frame = Frame::containing_address(PhysicalAddress::new(address - crate::PHYS_OFFSET));
            let result = active_table.map_to(page, frame, EntryFlags::PRESENT | EntryFlags::WRITABLE | EntryFlags::NO_EXECUTE);
            result.flush(&mut active_table);
        }

        let lpss = SerialPort::<Mmio<u32>>::new(
            crate::PHYS_OFFSET + 0xFE032000
        );
        lpss.init();

        *LPSS.lock() = Some(lpss);
    }
}
