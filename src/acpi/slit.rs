use crate::{
    acpi::{rxsdt::Rxsdt, sdt::Sdt, RXSDT_ENUM},
    find_one_sdt,
    memory::{round_up_pages, PAGE_SIZE},
    numa::{self},
};
use core::{ops::Add, slice};
use hashbrown::HashMap;
use rmm::{Arch, BumpAllocator, FrameAllocator, FrameCount};
use spin::once::Once;

#[derive(Debug)]
pub struct Slit {
    sdt: &'static Sdt,
    no: u64,
    address: *const u8,
}

impl Slit {
    pub fn new(sdt: &'static Sdt) -> Self {
        Self {
            sdt,
            no: unsafe { *(sdt.data_address() as *const u64) },
            address: (sdt.data_address() + 8) as *const u8,
        }
    }
    pub fn init<A: Arch>(&self, allocator: &mut BumpAllocator<A>) -> &'static mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.address.cast_mut(), (self.no * self.no) as usize) }
    }
}

pub fn init<A: Arch>(allocator: &mut BumpAllocator<A>, distances: &Once<&'static [u8]>) {
    if let Some(rxsdt) = RXSDT_ENUM.get() {
        for sdt_addr in rxsdt.iter() {
            let sdt =
                unsafe { &*(crate::memory::RmmA::phys_to_virt(sdt_addr).data() as *const Sdt) };
            if &sdt.signature == b"SLIT" {
                let slit = Slit::new(sdt);
                distances.call_once(|| slit.init(allocator));
                return;
            }
        }
    }
}
