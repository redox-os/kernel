use crate::{
    acpi::sdt::Sdt,
    find_one_sdt,
    numa::{self, NumaNode, NUMA_NODES},
};
use core::ops::Add;
use hashbrown::HashMap;

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
    pub fn init(&self, numa_nodes: &mut HashMap<u32, NumaNode>) {
        let address = self.address;
        let ndom = NUMA_NODES.get().unwrap().len() as u32;

        for i in 0..ndom {
            for j in i..ndom {
                // ignore distances from a domain to itself, since it is always 10
                if i != j {
                    numa::set_distance(numa_nodes, i, j, unsafe {
                        *address.add((i + ndom * j) as usize)
                    });
                    numa::set_distance(numa_nodes, j, i, unsafe {
                        *address.add((i + ndom * j) as usize)
                    });
                }
            }
        }
    }
}

pub fn init(numa_nodes: &mut HashMap<u32, NumaNode>) {
    let slit = Slit::new(find_one_sdt!("SLIT"));
    slit.init(numa_nodes);
}
