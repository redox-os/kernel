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
    let mut gicrs = Vec::new();
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
            MadtEntry::Gicr(gicd) => {
                gicrs.push(gicd);
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
            for _gicc in giccs {
                let mut gic_cpu_if = GicV3CpuIf;
                unsafe { gic_cpu_if.init() };
                log::info!("GIC CPU: {:#x?}", gic_cpu_if);
                let mut gicrs_addrs: Vec<(usize, usize)> = Vec::new();
                for discovery_range in gicrs {
                    let range_phys_base =
                        PhysicalAddress::new(discovery_range.discovery_range_base_address as usize);
                    let range_len = discovery_range.discovery_range_length as usize;

                    // Map the entire discovery range
                    let range_virt_base = unsafe { map_device_memory(range_phys_base, range_len) };

                    const GICR_STRIDE: usize = 0x20000; // 128KB (2 * 64KB pages)
                    for offset in (0..range_len).step_by(GICR_STRIDE) {
                        let current_gicr_base_virt = range_virt_base.add(offset);

                        // Read GICR_TYPER to identify the processor and the 'Last' flag
                        let typer_addr = current_gicr_base_virt.add(8);
                        let typer_val =
                            unsafe { core::ptr::read_volatile((typer_addr.data()) as *const u32) };
                        let is_last = (typer_val & (1 << 4)) != 0;

                        // Push the (base_address, size) tuple into the vector
                        gicrs_addrs.push((current_gicr_base_virt.data(), GICR_STRIDE));

                        log::info!(
                            "Discovered GICR at base {:#x} with size {:#x}",
                            current_gicr_base_virt.data(),
                            GICR_STRIDE
                        );

                        if is_last {
                            break; // Last redistributor in this range
                        }
                    }
                }
                let gic = GicV3 {
                    gic_dist_if,
                    gic_cpu_if,
                    gicrs: gicrs_addrs,
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
