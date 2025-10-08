use core::mem;

use super::{find_sdt, sdt::Sdt, GenericAddressStructure};
use crate::{
    device::serial::COM1,
    devices::{serial::SerialKind, uart_pl011},
    log::LOG,
    memory::{map_device_memory, PhysicalAddress, PAGE_SIZE},
};

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Spcr {
    pub header: Sdt,
    pub interface_type: u8,
    _reserved: [u8; 3],
    pub base_address: GenericAddressStructure,
    pub interrupt_type: u8,
    pub irq: u8,
    pub gsiv: u32,
    pub configured_baud_rate: u8,
    pub parity: u8,
    pub stop_bits: u8,
    pub flow_control: u8,
    pub terminal_type: u8,
    pub language: u8,
    pub pci_device_id: u16,
    pub pci_vendor_id: u16,
    pub pci_bus: u8,
    pub pci_device: u8,
    pub pci_function: u8,
    pub pci_flags: u32,
    pub pci_segment: u8,
    /*TODO: these fields are optional based on the table revision
    pub uart_clock_frequency: u32,
    pub precise_baud_rate: u32,
    pub namespace_string_length: u16,
    pub namespace_string_offset: u16,
    */
    // namespace_string
}

impl Spcr {
    pub fn init() {
        let spcr_sdt = find_sdt("SPCR");
        let spcr = if spcr_sdt.len() == 1 {
            match Spcr::new(spcr_sdt[0]) {
                Some(spcr) => spcr,
                None => {
                    warn!("Failed to parse SPCR");
                    return;
                }
            }
        } else {
            warn!("Unable to find SPCR");
            return;
        };

        if spcr.base_address.address == 0 {
            // Serial disabled
            return;
        }

        let serial_was_empty = !matches!(*COM1.lock(), SerialKind::NotPresent);
        if spcr.header.revision >= 2 {
            match spcr.interface_type {
                3 => {
                    // PL011
                    if spcr.base_address.address_space == 0
                        && spcr.base_address.bit_width == 32
                        && spcr.base_address.bit_offset == 0
                        && spcr.base_address.access_size == 3
                    {
                        let virt = unsafe {
                            map_device_memory(
                                PhysicalAddress::new(spcr.base_address.address as usize),
                                PAGE_SIZE,
                            )
                        };
                        let serial_port = uart_pl011::SerialPort::new(virt.data(), false);
                        *COM1.lock() = SerialKind::Pl011(serial_port)
                    } else {
                        warn!(
                            "SPCR unsuppoted address for PL011 {:#x?}",
                            spcr.base_address
                        );
                    }
                }
                //TODO: support more types!
                unsupported => {
                    warn!(
                        "SPCR revision {} unsupported interface type {}",
                        spcr.header.revision, unsupported
                    );
                }
            }
        } else if spcr.header.revision == 1 {
            match spcr.interface_type {
                //TODO: support more types!
                unsupported => {
                    warn!("SPCR revision 1 unsupported interface type {}", unsupported);
                }
            }
        } else {
            warn!("SPCR unsupported revision {}", spcr.header.revision);
        }
        let mut serial_port = COM1.lock();
        if serial_was_empty && !matches!(*serial_port, SerialKind::NotPresent) {
            // backfill logs since the heap is loaded
            if let Some(ref mut early_log) = *LOG.lock() {
                let (s1, s2) = early_log.read();
                if !s1.is_empty() {
                    serial_port.write(s1);
                }
                if !s2.is_empty() {
                    serial_port.write(s2);
                }
            }
        }
    }

    pub fn new(sdt: &'static Sdt) -> Option<&'static Spcr> {
        if &sdt.signature == b"SPCR" && sdt.length as usize >= mem::size_of::<Spcr>() {
            Some(unsafe { &*((sdt as *const Sdt) as *const Spcr) })
        } else {
            None
        }
    }
}
