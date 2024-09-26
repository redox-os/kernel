use crate::memory::KernelMapper;
use alloc::boxed::Box;

use super::get_sdt;

pub trait Rxsdt {
    fn iter(&self) -> Box<dyn Iterator<Item = usize>>;

    fn map_all(&self) {
        let mut mapper = KernelMapper::lock();
        for sdt in self.iter() {
            get_sdt(sdt, &mut mapper);
        }
    }
}
