use alloc::boxed::Box;
use rmm::PhysicalAddress;

use crate::acpi::{RxsdtEnum, sdt::Sdt};

pub trait Rxsdt {
    fn iter(&self) -> RxsdtIter;
}

pub struct RxsdtIter {
    pub sdt: &'static Sdt,
    pub i: usize,
    pub rxsdt_enum: RxsdtEnum,
}

impl Iterator for RxsdtIter {
    type Item = PhysicalAddress;
    fn next(&mut self) -> Option<Self::Item> {
        if self.i < self.sdt.data_len() / size_of::<u64>() {
            let item = unsafe {
                match self.rxsdt_enum{
                    RxsdtEnum::Rsdt(_) => PhysicalAddress::new(core::ptr::read_unaligned((self.sdt.data_address() as *const u32).add(self.i)) as usize),
                    RxsdtEnum::Xsdt(_) => PhysicalAddress::new(core::ptr::read_unaligned((self.sdt.data_address() as *const u64).add(self.i)) as usize),
                } 
            };
            self.i += 1;
            Some(item)
        } else {
            None
        }
    }
}
