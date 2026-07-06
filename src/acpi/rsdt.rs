use alloc::boxed::Box;
use core::convert::TryFrom;
use rmm::PhysicalAddress;

use crate::acpi::{rxsdt::RxsdtIter, RxsdtEnum};

use super::{rxsdt::Rxsdt, sdt::Sdt};

#[derive(Debug)]
pub struct Rsdt(&'static Sdt);

impl Rsdt {
    pub fn new(sdt: &'static Sdt) -> Option<Rsdt> {
        if &sdt.signature == b"RSDT" {
            Some(Rsdt(sdt))
        } else {
            None
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        let length =
            usize::try_from(self.0.length).expect("expected 32-bit length to fit within usize");

        unsafe { core::slice::from_raw_parts(self.0 as *const _ as *const u8, length) }
    }
}

impl Rxsdt for Rsdt {
    fn iter(&self) -> RxsdtIter {
        RxsdtIter {
            sdt: self.0,
            i: 0,
            rxsdt_enum: RxsdtEnum::Rsdt(Rsdt(self.0)),
        }
    }
}
