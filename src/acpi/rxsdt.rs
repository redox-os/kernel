use alloc::boxed::Box;
use rmm::PhysicalAddress;

use crate::acpi::sdt::Sdt;

pub trait Rxsdt {
    fn iter(&self) -> RxsdtIter;
}

pub struct RxsdtIter {
    pub sdt: &'static Sdt,
    pub i: usize,
}

impl Iterator for RxsdtIter {
    type Item = PhysicalAddress;
    fn next(&mut self) -> Option<Self::Item> {
        if self.i < self.sdt.data_len() / size_of::<u64>() {
            let item = unsafe {
                core::ptr::read_unaligned((self.sdt.data_address() as *const u64).add(self.i))
            };
            self.i += 1;
            Some(PhysicalAddress::new(item as usize))
        } else {
            None
        }
    }
}
