use crate::{
    devices::{serial::SerialKind, uart_16550::SerialPort},
    syscall::io::{Mmio, Pio},
};
use spin::Mutex;

pub static COM1: Mutex<SerialKind> = Mutex::new(SerialKind::NotPresent);
pub static COM2: Mutex<SerialKind> = Mutex::new(SerialKind::NotPresent);

pub static LPSS: Mutex<SerialKind> = Mutex::new(SerialKind::NotPresent);

pub unsafe fn init() {
    #[cfg(feature = "system76_ec_debug")]
    super::system76_ec::init();

    if cfg!(not(feature = "serial_debug")) {
        // FIXME remove serial_debug feature once ACPI SPCR is respected on UEFI boots.
        return;
    }

    let mut com1 = SerialPort::<Pio<u8>>::new(0x3F8);
    if com1.init().is_ok() {
        *COM1.lock() = SerialKind::Ns16550Pio(com1);
    }
    let mut com2 = SerialPort::<Pio<u8>>::new(0x2F8);
    if com2.init().is_ok() {
        *COM2.lock() = SerialKind::Ns16550Pio(com2);
    }

    // FIXME remove explicit LPSS handling once ACPI SPCR is supported
    if cfg!(not(feature = "lpss_debug")) {
        return;
    }

    let virt = {
        use crate::memory::{KernelMapper, PageFlags, PhysicalAddress};

        // TODO: Make this configurable
        let phys = PhysicalAddress::new(0xFE032000);

        let mut mapper = KernelMapper::lock_rw();
        let flags = PageFlags::new().write(true).execute(false);
        let (virt, flush) = unsafe {
            mapper
                .map_linearly(phys, flags)
                .expect("failed to map frame")
        };
        flush.flush();
        virt
    };

    let lpss = unsafe { SerialPort::<Mmio<u32>>::new(virt.data()) };
    if lpss.init().is_ok() {
        *LPSS.lock() = SerialKind::Ns16550u32(lpss);
    }
}
