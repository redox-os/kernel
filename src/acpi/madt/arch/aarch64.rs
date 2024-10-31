use alloc::{boxed::Box, vec::Vec};

use super::{Madt, MadtEntry};
use crate::{
    device::irqchip::{
        gic::{GenericInterruptController, GicCpuIf, GicDistIf},
        gicv3::{GicV3, GicV3CpuIf},
    },
    dtb::irqchip::{IrqChipItem, IRQ_CHIP},
    memory::{map_device_memory, PhysicalAddress, PAGE_SIZE},
};

pub(super) fn init(madt: Madt) {
    let mut gicd_opt = None;
    let mut giccs = Vec::new();
    for madt_entry in madt.iter() {
        println!("      {:#x?}", madt_entry);
        match madt_entry {
            MadtEntry::Gicc(gicc) => {
                giccs.push(gicc);
            }
            MadtEntry::Gicd(gicd) => {
                if gicd_opt.is_some() {
                    log::warn!("Only one GICD should be present on a system, ignoring this one");
                } else {
                    gicd_opt = Some(gicd);
                }
            }
            _ => {}
        }
    }
    let Some(gicd) = gicd_opt else {
        log::warn!("No GICD found");
        return;
    };
    let mut gic_dist_if = GicDistIf::default();
    unsafe {
        let phys = PhysicalAddress::new(gicd.physical_base_address as usize);
        let virt = map_device_memory(phys, PAGE_SIZE);
        gic_dist_if.init(virt.data());
    };
    log::info!("{:#x?}", gic_dist_if);
    match gicd.gic_version {
        1 | 2 => {
            for gicc in giccs {
                let mut gic_cpu_if = GicCpuIf::default();
                unsafe {
                    let phys = PhysicalAddress::new(gicc.physical_base_address as usize);
                    let virt = map_device_memory(phys, PAGE_SIZE);
                    gic_cpu_if.init(virt.data())
                };
                log::info!("{:#x?}", gic_cpu_if);
                let gic = GenericInterruptController {
                    gic_dist_if,
                    gic_cpu_if,
                    irq_range: (0, 0),
                };
                let chip = IrqChipItem {
                    phandle: 0,
                    parents: Vec::new(),
                    children: Vec::new(),
                    ic: Box::new(gic),
                };
                unsafe { IRQ_CHIP.irq_chip_list.chips.push(chip) };
                //TODO: support more GICCs
                break;
            }
        }
        3 => {
            for gicc in giccs {
                let mut gic_cpu_if = GicV3CpuIf;
                unsafe { gic_cpu_if.init() };
                log::info!("{:#x?}", gic_cpu_if);
                let gic = GicV3 {
                    gic_dist_if,
                    gic_cpu_if,
                    //TODO: get GICRs
                    gicrs: Vec::new(),
                    irq_range: (0, 0),
                };
                let chip = IrqChipItem {
                    phandle: 0,
                    parents: Vec::new(),
                    children: Vec::new(),
                    ic: Box::new(gic),
                };
                unsafe { IRQ_CHIP.irq_chip_list.chips.push(chip) };
                //TODO: support more GICCs
                break;
            }
        }
        _ => {
            log::warn!("unsupported GIC version {}", gicd.gic_version);
        }
    }
    unsafe { IRQ_CHIP.init(None) };
}
