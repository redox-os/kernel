use alloc::boxed::Box;

use crate::paging::KernelMapper;

use super::{get_sdt, sdt::Sdt};

pub trait Rxsdt {
    fn iter(&self) -> Box<dyn Iterator<Item = usize>>;

    fn map_all(&self) {
        let mut mapper = KernelMapper::lock();
        for sdt in self.iter() {
            get_sdt(sdt, &mut mapper);
        }
    }

    fn find(
        &self,
        signature: [u8; 4],
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
    ) -> Option<&'static Sdt> {
        for sdt in self.iter() {
            let sdt = unsafe { &*(sdt as *const Sdt) };

            if sdt.match_pattern(signature, oem_id, oem_table_id) {
                return Some(sdt);
            }
        }

        None
    }
}
