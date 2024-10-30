use alloc::{boxed::Box, vec::Vec};
use rmm::{Arch, PageFlags};

use super::{Madt, MadtEntry};
use crate::{
    device::irqchip::{
        gic::{GenericInterruptController, GicCpuIf, GicDistIf},
        gicv3::{GicV3, GicV3CpuIf},
    },
    dtb::irqchip::{InterruptController, IrqChipItem, IRQ_CHIP},
    memory::{Frame, KernelMapper, PhysicalAddress},
    paging::{entry::EntryFlags, RmmA},
};

unsafe fn map_gic_page(phys: PhysicalAddress) {
    let frame = Frame::containing(phys);
    let (_, result) = KernelMapper::lock()
        .get_mut()
        .expect("KernelMapper locked re-entrant while mapping memory for GIC")
        .map_linearly(
            frame.base(),
            PageFlags::new()
                .write(true)
                .custom_flag(EntryFlags::NO_CACHE.bits(), true),
        )
        .expect("failed to map memory for GIC");
    result.flush();
}

fn add_irqchip(irqchip: Box<dyn InterruptController>) {}

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
        map_gic_page(phys);
        gic_dist_if.init(RmmA::phys_to_virt(phys).data());
    };
    log::info!("{:#x?}", gic_dist_if);
    match gicd.gic_version {
        1 | 2 => {
            for gicc in giccs {
                let mut gic_cpu_if = GicCpuIf::default();
                unsafe {
                    let phys = PhysicalAddress::new(gicc.physical_base_address as usize);
                    map_gic_page(phys);
                    gic_cpu_if.init(RmmA::phys_to_virt(phys).data())
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
