pub mod irqchip;

use crate::startup::memory::{register_memory_region, BootloaderMemoryKind};
use alloc::vec::Vec;
use byteorder::{ByteOrder, BE};
use core::slice;
use fdt::{node::NodeProperty, Fdt};
use log::debug;
use spin::once::Once;

pub static DTB_BINARY: Once<Vec<u8>> = Once::new();

pub unsafe fn init(dtb: Option<(usize, usize)>) {
    let mut initialized = false;
    DTB_BINARY.call_once(|| {
        initialized = true;

        let mut binary = Vec::new();
        if let Some((dtb_base, dtb_size)) = dtb {
            let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
            binary.extend(data);
        };
        binary
    });
    if !initialized {
        println!("DTB_BINARY INIT TWICE!");
    }
}

pub fn travel_interrupt_ctrl(fdt: &Fdt) {
    if let Some(root_intr_parent) = fdt
        .root()
        .property("interrupt-parent")
        .and_then(NodeProperty::as_usize)
    {
        debug!("root parent = 0x{:08x}", root_intr_parent);
    }
    for node in fdt.all_nodes() {
        if node.property("interrupt-controller").is_some() {
            let compatible = node.property("compatible").unwrap().as_str().unwrap();
            let phandle = node.property("phandle").unwrap().as_usize().unwrap();
            let intr_cells = node.interrupt_cells().unwrap();
            let _intr = node
                .property("interrupt-parent")
                .and_then(NodeProperty::as_usize);
            let _intr_data = node.property("interrupts");

            debug!(
                "{}, compatible = {}, #interrupt-cells = 0x{:08x}, phandle = 0x{:08x}",
                node.name, compatible, intr_cells, phandle
            );
            if let Some(intr) = _intr {
                if let Some(intr_data) = _intr_data {
                    debug!("interrupt-parent = 0x{:08x}", intr);
                    debug!("interrupts begin:");
                    for chunk in intr_data.value.chunks(4) {
                        debug!("0x{:08x}, ", BE::read_u32(chunk));
                    }
                    debug!("interrupts end");
                }
            }
        }
    }
}

#[allow(unused)]
pub fn register_memory_ranges(dt: &Fdt) {
    for chunk in dt.memory().regions() {
        if let Some(size) = chunk.size {
            register_memory_region(
                chunk.starting_address as usize,
                size,
                BootloaderMemoryKind::Free,
            );
        }
    }
}

pub fn register_dev_memory_ranges(dt: &Fdt) {
    if cfg!(target_arch = "aarch64") {
        // work around for qemu-arm64
        // dev mem: 128MB - 1GB, see https://github.com/qemu/qemu/blob/master/hw/arm/virt.c for details
        let root_node = dt.root();
        let is_qemu_virt = root_node.model().contains("linux,dummy-virt");

        if is_qemu_virt {
            register_memory_region(0x08000000, 0x08000000, BootloaderMemoryKind::Device);
            register_memory_region(0x10000000, 0x30000000, BootloaderMemoryKind::Device);
            return;
        }
    }

    let Some(soc_node) = dt.find_node("/soc") else {
        log::warn!("failed to find /soc in devicetree");
        return;
    };
    let Some(reg) = soc_node.ranges() else {
        log::warn!("devicetree /soc has no ranges");
        return;
    };
    for chunk in reg {
        log::debug!(
            "dev mem 0x{:08x} 0x{:08x} 0x{:08x} 0x{:08x}",
            chunk.child_bus_address_hi,
            chunk.child_bus_address,
            chunk.parent_bus_address,
            chunk.size
        );

        register_memory_region(
            chunk.parent_bus_address,
            chunk.size,
            BootloaderMemoryKind::Device,
        );
    }

    // also add all soc-internal devices please because they might not be shown in ranges
    for device in soc_node.children() {
        if let Some(reg) = device.reg() {
            for entry in reg {
                if let Some(size) = entry.size {
                    let addr = entry.starting_address as usize;
                    log::debug!("soc device {} 0x{:08x} 0x{:08x}", device.name, addr, size);

                    register_memory_region(addr, size, BootloaderMemoryKind::Device);
                }
            }
        }
    }
}

pub fn diag_uart_range<'a>(dtb: &'a Fdt) -> Option<(usize, usize, bool, bool, &'a str)> {
    let stdout_path = dtb.chosen().stdout()?;
    let uart_node = stdout_path.node();
    let skip_init = uart_node.property("skip-init").is_some();
    let cts_event_walkaround = uart_node.property("cts-event-walkaround").is_some();
    let compatible = uart_node
        .property("compatible")
        .and_then(NodeProperty::as_str)?;

    let mut reg = uart_node.reg()?;
    let memory = reg.nth(0)?;

    Some((
        memory.starting_address as usize,
        memory.size?,
        skip_init,
        cts_event_walkaround,
        compatible,
    ))
}

#[allow(unused)]
pub fn fill_env_data(dt: &Fdt, env_base: usize) -> usize {
    if let Some(bootargs) = dt.chosen().bootargs() {
        let bootargs_len = bootargs.len();

        let env_base_slice =
            unsafe { slice::from_raw_parts_mut(env_base as *mut u8, bootargs_len) };
        env_base_slice[..bootargs_len].clone_from_slice(bootargs.as_bytes());

        bootargs_len
    } else {
        0
    }
}
