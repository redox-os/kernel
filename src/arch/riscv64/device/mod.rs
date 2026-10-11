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

fn string_property(name: &str) -> bool {
    name == "compatible"
        || name == "model"
        || name == "device_type"
        || name == "status"
        || name == "riscv,isa-base"
        || name == "riscv,isa"
        || name == "mmu-type"
        || name == "stdout-path"
}

fn print_property(prop: &NodeProperty, n_spaces: usize) {
    (0..n_spaces).for_each(|_| print!(" "));
    print!("{} =", prop.name);
    if string_property(prop.name)
        && let Some(str) = prop.as_str()
    {
        println!(" \"{}\"", str);
    } else if let Some(value) = prop.as_usize() {
        println!(" 0x{:08x}", value);
    } else {
        for v in prop.value {
            print!(" {:02x}", v);
        }
        println!();
    }
}
fn print_node(node: &FdtNode<'_, '_>, n_spaces: usize) {
    (0..n_spaces).for_each(|_| print!(" "));
    println!("{}/", node.name);
    for prop in node.properties() {
        print_property(&prop, n_spaces + 4);
    }

    for child in node.children() {
        print_node(&child, n_spaces + 4);
    }
}

pub(crate) fn dump_fdt(fdt: &Fdt) {
    if let Some(root) = fdt.find_node("/") {
        print_node(&root, 0);
    }
}

pub unsafe fn init(fdt: &Fdt, boot_hart_id: usize) -> usize {
    crate::dtb::irqchip::init(fdt);
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
