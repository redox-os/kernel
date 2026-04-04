use crate::{
    devices::{serial::SerialKind, uart_16550::SerialPort},
    memory::map_device_memory,
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

    let virt = unsafe {
        map_device_memory(
            // TODO: Make this configurable
            crate::memory::PhysicalAddress::new(0xFE032000),
            4,
        )
    };

    let lpss = unsafe { SerialPort::<Mmio<u32>>::new(virt.data()) };
    if lpss.init().is_ok() {
        *LPSS.lock() = SerialKind::Ns16550u32(lpss);
    }
}
