use crate::{
    arch::{device::irqchip::hlic, time},
    dtb::DTB_BINARY,
};
use fdt::{
    node::{FdtNode, NodeProperty},
    Fdt,
};

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

unsafe fn init_intc(cpu: &FdtNode) {
    let intc_node = cpu
        .children()
        .find(|x| x.name == "interrupt-controller")
        .unwrap();
    assert_eq!(intc_node.compatible().unwrap().first(), "riscv,cpu-intc");
    // This controller is hardwired into interrupt handler code and has no Mmios
    hlic::init(); // enable interrupts at HLIC level
}

pub unsafe fn init() {
    let data = DTB_BINARY.get().unwrap();
    let fdt = Fdt::new(data).unwrap();

    crate::dtb::irqchip::init(&fdt);

    let cpu = fdt.find_node(format!("/cpus/cpu@{}", 0).as_str()).unwrap();
    init_intc(&cpu);
    init_time(&fdt);
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

pub unsafe fn init_noncore() {
    let data = DTB_BINARY.get().unwrap();
    let fdt = Fdt::new(data).unwrap();

    init_clint(&fdt);
    serial::init(&fdt);
}

#[derive(Default)]
pub struct ArchPercpuMisc;
