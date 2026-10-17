use crate::{arch::time, dtb::irqchip::IrqChip};
use fdt::{
    node::{FdtNode, NodeProperty},
    Fdt,
};
use spin::Once;

pub mod cpu;
pub(crate) mod irqchip;
pub mod serial;

use crate::arch::device::irqchip::init_clint;

pub unsafe fn init(fdt: &Fdt, boot_hart_id: usize) -> usize {
    crate::dtb::irqchip::init(Some(fdt), None);
    let boot_hart_hlic_idx = IrqChip::phandle_to_ic_idx(
        fdt.find_all_nodes("/cpus/cpu")
            .find(|c| {
                str::parse::<usize>(&c.name[4..]).expect(" failed to parse hart_id of cpu node!")
                    == boot_hart_id
            })
            .and_then(|c| {
                c.children().find(|h| {
                    h.compatible()
                        .is_some_and(|comp| comp.all().any(|comp| comp == "riscv,cpu-intc"))
                })
            })
            .and_then(|h| h.property("phandle"))
            .and_then(|p| p.as_usize())
            .expect("Failed to find or parse phandle of hlic!") as u32,
    )
    .expect("No ic found for hlic phandle!");

    init_time(fdt);

    boot_hart_hlic_idx
}

fn init_time(fdt: &Fdt) {
    let cpus = fdt.find_node("/cpus").unwrap();
    let clock_freq = cpus
        .property("timebase-frequency")
        .unwrap()
        .as_usize()
        .unwrap();
    time::init(clock_freq);
}

pub unsafe fn init_noncore(fdt: &Fdt, boot_hart: usize) {
    unsafe {
        init_clint(&fdt, boot_hart);
        serial::init(&fdt);
    }
}

pub struct ArchPercpuMisc {
    pub hart_id: usize,
    pub hlic_idx: Once<usize>,
}

impl ArchPercpuMisc {
    // TODO find a way to actually initialize these
    // instead of using nonsense placeholder values?

    pub const fn default() -> Self {
        Self {
            hart_id: 0,
            hlic_idx: Once::new(),
        }
    }
}
