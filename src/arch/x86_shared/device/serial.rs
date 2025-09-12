#[cfg(feature = "lpss_debug")]
use crate::syscall::io::Mmio;
use crate::{devices::uart_16550::SerialPort, syscall::io::Pio};
use spin::Mutex;

pub static COM1: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x3F8));
pub static COM2: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x2F8));
// pub static COM3: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x3E8));
// pub static COM4: Mutex<SerialPort<Pio<u8>>> = Mutex::new(SerialPort::<Pio<u8>>::new(0x2E8));

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
            use rmm::PageFlags;

            use crate::{
                memory::{KernelMapper, PhysicalAddress},
                paging::VirtualAddress,
            };

            let mut mapper = KernelMapper::lock();
            let virt = VirtualAddress::new(address);
            let phys = PhysicalAddress::new(address - crate::PHYS_OFFSET);
            let flags = PageFlags::new().write(true).execute(false);
            unsafe {
                mapper
                    .get_mut()
                    .unwrap()
                    .map_phys(virt, phys, flags)
                    .expect("failed to map frame")
                    .flush();
            }
        }

        let lpss = unsafe { SerialPort::<Mmio<u32>>::new(crate::PHYS_OFFSET + 0xFE032000) };
        lpss.init();

        *LPSS.lock() = Some(lpss);
    }
}
