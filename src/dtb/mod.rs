pub mod irqchip;

use crate::{
    dtb::irqchip::IrqCell,
    startup::memory::{register_memory_region, BootloaderMemoryKind},
};
use byteorder::{ByteOrder, BE};
use core::slice;
use fdt::{
    node::{FdtNode, NodeProperty},
    standard_nodes::MemoryRegion,
    Fdt,
};
use spin::once::Once;

/// Represents the in-memory DTB (DeviceTree) binary.
pub static DTB_BINARY: Once<&'static [u8]> = Once::new();

/// Initializes the DTB from the provided base address and size.
///
/// # Safety
///
/// Caller must ensure the base address and size reference valid memory.
///
/// The referenced memory must contain a valid DTB for the underlying system.
///
/// The referenced memory must **not** be mutated for the duration of kernel run-time.
pub unsafe fn init(dtb: Option<(usize, usize)>) {
    let mut initialized = false;
    DTB_BINARY.call_once(|| {
        initialized = true;

        if let Some((dtb_base, dtb_size)) = dtb {
            // SAFETY: `dtb_base` + `dtb_size` reference valid memory due to caller invariants
            unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) }
        } else {
            &[]
        }
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
            let Some(compatible) = node.property("compatible") else {
                continue;
            };
            let compatible = compatible.as_str().unwrap();
            let Some(phandle) = node.property("phandle") else {
                continue;
            };
            let phandle = phandle.as_usize().unwrap();
            if let Some(intr_cells) = node.interrupt_cells() {
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
        warn!("failed to find /soc in devicetree");
        return;
    };
    let Some(reg) = soc_node.ranges() else {
        warn!("devicetree /soc has no ranges");
        return;
    };
    for chunk in reg {
        debug!(
            "dev mem 0x{:08x} 0x{:08x} 0x{:08x} 0x{:08x}",
            chunk.child_bus_address_hi,
            chunk.child_bus_address,
            chunk.parent_bus_address,
            chunk.size
        );

        /*TODO: soc memory may contain all free memory!
        register_memory_region(
            chunk.parent_bus_address,
            chunk.size,
            BootloaderMemoryKind::Device,
        );*/
    }

    // also add all soc-internal devices because they might not be shown in ranges
    // (identity-mapped soc bus may have empty ranges)
    for device in soc_node.children() {
        if let Some(reg) = device.reg() {
            for entry in reg {
                if let Some(size) = entry.size {
                    let addr = entry.starting_address as usize;
                    if let Some(mapped_addr) = get_mmio_address(dt, &device, &entry) {
                        debug!(
                            "soc device {} 0x{:08x} -> 0x{:08x} size 0x{:08x}",
                            device.name, addr, mapped_addr, size
                        );
                        register_memory_region(mapped_addr, size, BootloaderMemoryKind::Device);
                    }
                }
            }
        }
    }
}

pub fn get_mmio_address(fdt: &Fdt, _device: &FdtNode, region: &MemoryRegion) -> Option<usize> {
    /* DT spec 2.3.8 "ranges":
     * The ranges property provides a means of defining a mapping or translation between
     * the address space of the bus (the child address space) and the address space of the bus
     * node’s parent (the parent address space).
     * If the property is defined with an <empty> value, it specifies that the parent and child
     * address space is identical, and no address translation is required.
     * If the property is not present in a bus node, it is assumed that no mapping exists between
     * children of the node and the parent address space.
     */

    // FIXME assumes all the devices are connected to CPUs via the /soc bus
    let mut mapped_addr = region.starting_address as usize;
    let size = region.size.unwrap_or(0).saturating_sub(1);
    let last_address = mapped_addr.saturating_add(size);
    if let Some(parent) = fdt.find_node("/soc") {
        let mut ranges = parent.ranges().map(|f| f.peekable())?;
        if ranges.peek().is_some() {
            let parent_range = ranges.find(|x| {
                x.child_bus_address <= mapped_addr && last_address - x.child_bus_address <= x.size
            })?;
            mapped_addr = parent_range
                .parent_bus_address
                .checked_add(mapped_addr - parent_range.child_bus_address)?;
            let _ = mapped_addr.checked_add(size)?;
        }
    }
    Some(mapped_addr)
}

pub fn interrupt_parent<'a>(fdt: &'a Fdt, node: &'a FdtNode) -> Option<FdtNode<'a, 'a>> {
    // FIXME traverse device tree up
    node.interrupt_parent()
        .or_else(|| fdt.find_node("/soc").and_then(|soc| soc.interrupt_parent()))
        .or_else(|| fdt.find_node("/").and_then(|node| node.interrupt_parent()))
}

pub fn get_interrupt(fdt: &Fdt, node: &FdtNode, idx: usize) -> Option<IrqCell> {
    let interrupts = node.property("interrupts").unwrap();
    let parent_interrupt_cells = interrupt_parent(fdt, node)
        .unwrap()
        .interrupt_cells()
        .unwrap();
    let mut intr = interrupts
        .value
        .as_chunks::<4>()
        .0
        .iter()
        .map(|f| BE::read_u32(f))
        .skip(parent_interrupt_cells * idx);
    match parent_interrupt_cells {
        1 => Some(IrqCell::L1(intr.next()?)),
        2 if let Ok([a, b]) = intr.next_chunk() => Some(IrqCell::L2(a, b)),
        3 if let Ok([a, b, c]) = intr.next_chunk() => Some(IrqCell::L3(a, b, c)),
        _ => None,
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
    let address = get_mmio_address(dtb, &uart_node, &memory)?;

    Some((
        address,
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
