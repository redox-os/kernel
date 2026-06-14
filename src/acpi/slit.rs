use crate::{
    acpi::sdt::Sdt,
    find_one_sdt,
    numa::{self, NumaNode, NUMA_NODES, NUMBER_OF_DOMAINS},
};
use core::ops::Add;
use hashbrown::HashMap;

#[derive(Debug)]
pub struct Slit {
    sdt: &'static Sdt,
    no: u64,
    address: usize,
}

impl Slit {
    pub fn new(sdt: &'static Sdt) -> Self {
        Self {
            sdt,
            no: unsafe { *(sdt.data_address() as *const u64) },
            address: sdt.data_address() + 8,
        }
    }
    pub fn init(&self) {
        let ndom = *NUMBER_OF_DOMAINS.get().unwrap();
        let address = self.address as *const u8;

        for i in 0..ndom {
            for j in i..ndom {
                if i != j {
                    unsafe {
                        numa::set_distance(i, j, unsafe { *address.add((i + ndom * j) as usize) });
                        numa::set_distance(j, i, unsafe { *address.add((i + ndom * j) as usize) });
                    }
                } else {
                    unsafe {
                        numa::set_distance(i, j, 10);
                    }
                }
            }
        }
    }
}

pub fn init() {
    let slit = Slit::new(find_one_sdt!("SLIT"));
    slit.init();
}
