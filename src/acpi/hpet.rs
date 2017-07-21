use core::{mem, ptr};

use super::sdt::Sdt;
use core::intrinsics::{volatile_load, volatile_store};

use memory::Frame;
use paging::{entry, ActivePageTable, PhysicalAddress, Page, VirtualAddress};

#[repr(packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GenericAddressStructure {
    address_space: u8,
    bit_width: u8,
    bit_offset: u8,
    access_size: u8,
    pub address: u64,
}

#[repr(packed)]
#[derive(Debug)]
pub struct Hpet {
    pub header: Sdt,

    pub hw_rev_id: u8,
    pub comparator_descriptor: u8,
    pub pci_vendor_id: u16,

    pub base_address: GenericAddressStructure,

    pub hpet_number: u8,
    pub min_periodic_clk_tick: u16,
    pub oem_attribute: u8
}

impl Hpet {
    pub fn new(sdt: &'static Sdt, active_table: &mut ActivePageTable) -> Option<Hpet> {
        if &sdt.signature == b"HPET" && sdt.length as usize >= mem::size_of::<Hpet>() {
            let s = unsafe { ptr::read((sdt as *const Sdt) as *const Hpet) };
            unsafe { s.base_address.init(active_table) };
            Some(s)
        } else {
            None
        }
    }
}

impl GenericAddressStructure {
    pub unsafe fn init(&self, active_table: &mut ActivePageTable) {
        let page = Page::containing_address(VirtualAddress::new(self.address as usize));
        let frame = Frame::containing_address(PhysicalAddress::new(self.address as usize));
        let result = active_table.map_to(page, frame, entry::PRESENT | entry::WRITABLE | entry::NO_EXECUTE);
        result.flush(active_table);
    }
    
    pub unsafe fn read_u64(&self, offset: usize) -> u64{
        volatile_load((self.address as usize + offset) as *const u64)
    }

    pub unsafe fn write_u64(&mut self, offset: usize, value: u64) {
        volatile_store((self.address as usize + offset) as *mut u64, value);
    }
}
