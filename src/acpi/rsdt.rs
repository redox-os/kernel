use core::convert::TryFrom;
use core::mem;
use alloc::boxed::Box;

use super::sdt::Sdt;
use super::rxsdt::Rxsdt;

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
        let length = usize::try_from(self.0.length)
            .expect("expected 32-bit length to fit within usize");

        unsafe {
            core::slice::from_raw_parts(self.0 as *const _ as *const u8, length)
        }
    }
}

impl Rxsdt for Rsdt {
    fn iter(&self) -> Box<dyn Iterator<Item = usize>> {
        Box::new(RsdtIter {
            sdt: self.0,
            i: 0
        })
    }
}

pub struct RsdtIter {
    sdt: &'static Sdt,
    i: usize
}

impl Iterator for RsdtIter {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        if self.i < self.sdt.data_len()/mem::size_of::<u32>() {
            let item = unsafe { *(self.sdt.data_address() as *const u32).add(self.i) };
            self.i += 1;
            Some(item as usize)
        } else {
            None
        }
    }
}
