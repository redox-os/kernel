use core::{mem, ptr};

use core::ptr::{read_volatile, write_volatile};

use crate::{
    find_one_sdt,
    memory::{map_device_memory, PhysicalAddress, PAGE_SIZE},
};

use super::{sdt::Sdt, GenericAddressStructure, ACPI_TABLE};

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Hpet {
    pub header: Sdt,

    pub hw_rev_id: u8,
    pub comparator_descriptor: u8,
    pub pci_vendor_id: u16,

    pub base_address: GenericAddressStructure,

    pub hpet_number: u8,
    pub min_periodic_clk_tick: u16,
    pub oem_attribute: u8,
}

impl Hpet {
    pub fn init() {
        let hpet = Hpet::new(find_one_sdt!("HPET"));

        if let Some(hpet) = hpet {
            debug!("  HPET: {:X}", hpet.hpet_number);

            let mut hpet_t = ACPI_TABLE.hpet.write();
            *hpet_t = Some(hpet);
        }
    }

    pub fn new(sdt: &'static Sdt) -> Option<Hpet> {
        if &sdt.signature == b"HPET" && sdt.length as usize >= mem::size_of::<Hpet>() {
            let s = unsafe { ptr::read((sdt as *const Sdt) as *const Hpet) };
            if s.base_address.address_space == 0 {
                unsafe { s.map() };
                Some(s)
            } else {
                warn!(
                    "HPET has unsupported address space {}",
                    s.base_address.address_space
                );
                None
            }
        } else {
            None
        }
    }
}

//TODO: x86 use assumes only one HPET and only one GenericAddressStructure
#[cfg(target_arch = "x86")]
impl Hpet {
    pub unsafe fn map(&self) {
        unsafe {
            use crate::{
                memory::{Frame, KernelMapper},
                paging::{entry::EntryFlags, Page, VirtualAddress},
            };
            use rmm::PageFlags;

            let frame = Frame::containing(PhysicalAddress::new(self.base_address.address as usize));
            let page = Page::containing_address(VirtualAddress::new(crate::HPET_OFFSET));

            KernelMapper::lock()
            .get_mut()
            .expect(
                "KernelMapper locked re-entrant while mapping memory for GenericAddressStructure",
            )
            .map_phys(
                page.start_address(),
                frame.base(),
                PageFlags::new()
                    .write(true)
                    .custom_flag(EntryFlags::NO_CACHE.bits(), true),
            )
            .expect("failed to map memory for GenericAddressStructure")
            .flush();
        }
    }

    pub unsafe fn read_u64(&self, offset: usize) -> u64 {
        unsafe { read_volatile((crate::HPET_OFFSET + offset) as *const u64) }
    }

    pub unsafe fn write_u64(&mut self, offset: usize, value: u64) {
        unsafe {
            write_volatile((crate::HPET_OFFSET + offset) as *mut u64, value);
        }
    }
}

#[cfg(not(target_arch = "x86"))]
impl Hpet {
    pub unsafe fn map(&self) {
        unsafe {
            map_device_memory(
                PhysicalAddress::new(self.base_address.address as usize),
                PAGE_SIZE,
            );
        }
    }

    pub unsafe fn read_u64(&self, offset: usize) -> u64 {
        unsafe {
            read_volatile(
                (self.base_address.address as usize + offset + crate::PHYS_OFFSET) as *const u64,
            )
        }
    }

    pub unsafe fn write_u64(&mut self, offset: usize, value: u64) {
        unsafe {
            write_volatile(
                (self.base_address.address as usize + offset + crate::PHYS_OFFSET) as *mut u64,
                value,
            );
        }
    }
}
