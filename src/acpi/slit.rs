use crate::acpi::{rxsdt::Rxsdt, sdt::Sdt, RXSDT_ENUM};
use core::slice;
use rmm::Arch;
use spin::once::Once;

#[derive(Debug)]
pub struct Slit {
    _sdt: &'static Sdt,
    no: u64,
    address: *const u8,
}

impl Slit {
    pub fn new(_sdt: &'static Sdt) -> Self {
        Self {
            _sdt,
            no: unsafe { *(_sdt.data_address() as *const u64) },
            address: (_sdt.data_address() + 8) as *const u8,
        }
    }
    pub fn init(&self) -> &'static mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.address.cast_mut(), (self.no * self.no) as usize) }
    }
}

pub fn init(distances: &Once<&'static [u8]>) {
    if let Some(rxsdt) = RXSDT_ENUM.get() {
        for sdt_addr in rxsdt.iter() {
            let sdt =
                unsafe { &*(crate::memory::RmmA::phys_to_virt(sdt_addr).data() as *const Sdt) };
            if &sdt.signature == b"SLIT" {
                let slit = Slit::new(sdt);
                distances.call_once(|| slit.init());
                return;
            }
        }
    }
}
