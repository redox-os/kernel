use alloc::{boxed::Box, vec::Vec};

use super::{Madt, MadtEntry};
use crate::{
    arch::device::irqchip::{
        gic::{GenericInterruptController, GicCpuIf, GicDistIf},
        gicv3::{GicV3, GicV3CpuIf},
    },
    dtb::irqchip::{init_with_chips, IrqChipItem},
    memory::{map_device_memory, PhysicalAddress, PAGE_SIZE},
};

pub(super) fn init(madt: Madt) {
    let mut gicd_opt = None;
    let mut giccs = Vec::new();
    for madt_entry in madt.iter() {
        debug!("      {:#x?}", madt_entry);
        match madt_entry {
            MadtEntry::Gicc(gicc) => {
                giccs.push(gicc);
            }
            MadtEntry::Gicd(gicd) => {
                if gicd_opt.is_some() {
                    warn!("Only one GICD should be present on a system, ignoring this one");
                } else {
                    gicd_opt = Some(gicd);
                }
            }
            _ => {}
        }
    }
    let Some(gicd) = gicd_opt else {
        warn!("No GICD found");
        return;
    };
    let mut chips = Vec::new();
    let mut gic_dist_if = GicDistIf::default();
    unsafe {
        let phys = PhysicalAddress::new(gicd.physical_base_address as usize);
        let virt = map_device_memory(phys, PAGE_SIZE);
        gic_dist_if.init(virt.data());
    };
    info!("{:#x?}", gic_dist_if);
    match gicd.gic_version {
        1 | 2 => {
            #[allow(clippy::never_loop)]
            for gicc in giccs {
                let mut gic_cpu_if = GicCpuIf::default();
                unsafe {
                    let phys = PhysicalAddress::new(gicc.physical_base_address as usize);
                    let virt = map_device_memory(phys, PAGE_SIZE);
                    gic_cpu_if.init(virt.data())
                };
                info!("{:#x?}", gic_cpu_if);
                let gic = GenericInterruptController {
                    gic_dist_if,
                    gic_cpu_if,
                    irq_range: (0, 0),
                };
                chips.push(IrqChipItem {
                    phandle: 0,
                    parents: Vec::new(),
                    children: Vec::new(),
                    ic: Box::new(gic),
                });
                //TODO: support more GICCs
                break;
            }
        }
        3 => {
            #[allow(clippy::never_loop)]
            for gicc in giccs {
                let mut gic_cpu_if = GicV3CpuIf;
                unsafe { gic_cpu_if.init() };
                info!("{:#x?}", gic_cpu_if);
                let gic = GicV3 {
                    gic_dist_if,
                    gic_cpu_if,
                    //TODO: get GICRs
                    gicrs: Vec::new(),
                    irq_range: (0, 0),
                };
                chips.push(IrqChipItem {
                    phandle: 0,
                    parents: Vec::new(),
                    children: Vec::new(),
                    ic: Box::new(gic),
                });
                //TODO: support more GICCs
                break;
            }
        }
        _ => {
            warn!("unsupported GIC version {}", gicd.gic_version);
        }
    }
    init_with_chips(chips);
}
