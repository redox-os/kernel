#[cfg(dtb)]
pub mod irqchip;
pub mod serial;

#[cfg(dtb)]
use crate::dtb::irqchip::IrqCell;
use crate::startup::memory::{register_memory_region, BootloaderMemoryKind};
use core::slice;
use fdt::{
    node::{CellSizes, FdtNode, NodeProperty},
    standard_nodes::MemoryRegion,
    Fdt,
};
use rmm::PhysicalAddress;
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
#[cfg_attr(not(dtb), expect(dead_code))]
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

#[cfg_attr(not(dtb), expect(dead_code))]
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
                        for &chunk in intr_data.value.as_chunks::<4>().0 {
                            debug!("0x{:08x}, ", u32::from_be_bytes(chunk));
                        }
                    }
                    debug!("interrupts end");
                }
            }
        }
    }
}

fn cells_to_usize(bytes: &[u8], cells: usize) -> Option<usize> {
    let value = match cells {
        1 => u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as u64,
        2 => u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?),
        _ => return None,
    };

    usize::try_from(value).ok()
}

fn explicit_cell_sizes(node: FdtNode<'_, '_>) -> Option<CellSizes> {
    fn cell_count(property: NodeProperty<'_>) -> Option<usize> {
        let bytes: [u8; 4] = property.value.try_into().ok()?;
        usize::try_from(u32::from_be_bytes(bytes)).ok()
    }

    Some(CellSizes {
        address_cells: cell_count(node.property("#address-cells")?)?,
        size_cells: cell_count(node.property("#size-cells")?)?,
    })
}

fn visit_address_size_pairs(
    property: NodeProperty<'_>,
    cell_sizes: CellSizes,
    node_name: &str,
    visit: &mut impl FnMut(usize, usize),
) {
    let Some(stride_cells) = cell_sizes.address_cells.checked_add(cell_sizes.size_cells) else {
        warn!("invalid reserved-memory reg property for {node_name}");
        return;
    };
    let Some(stride) = stride_cells.checked_mul(size_of::<u32>()) else {
        warn!("invalid reserved-memory reg property for {node_name}");
        return;
    };
    let Some(address_bytes) = cell_sizes.address_cells.checked_mul(size_of::<u32>()) else {
        warn!("invalid reserved-memory reg property for {node_name}");
        return;
    };

    if stride == 0 || property.value.is_empty() || property.value.len() % stride != 0 {
        warn!("invalid reserved-memory reg property for {node_name}");
        return;
    }

    for pair in property.value.chunks_exact(stride) {
        let Some(address) = cells_to_usize(pair, cell_sizes.address_cells) else {
            warn!("unsupported reserved-memory address for {node_name}");
            continue;
        };
        let Some(size) = cells_to_usize(&pair[address_bytes..], cell_sizes.size_cells) else {
            warn!("unsupported reserved-memory size for {node_name}");
            continue;
        };

        if address.checked_add(size).is_none() {
            warn!("reserved-memory range overflows for {node_name}");
        } else if size != 0 {
            debug!(
                "reserved-memory {} 0x{:08x} size 0x{:08x}",
                node_name, address, size
            );
            visit(address, size);
        }
    }
}

fn visit_fdt_memory_reservations(dt: &Fdt, visit: &mut impl FnMut(usize, usize)) {
    const FDT_HEADER_SIZE: usize = 10 * size_of::<u32>();
    const STRUCTURE_BLOCK_OFFSET_FIELD: usize = 8;
    const RESERVATION_MAP_OFFSET_FIELD: usize = 16;
    const RESERVATION_ENTRY_SIZE: usize = 2 * size_of::<u64>();

    let data = &dt.raw_data()[..dt.total_size()];
    let read_offset = |field: usize| -> Option<usize> {
        let bytes: [u8; 4] = data
            .get(field..field.checked_add(size_of::<u32>())?)?
            .try_into()
            .ok()?;
        usize::try_from(u32::from_be_bytes(bytes)).ok()
    };
    let Some(mut offset) = read_offset(RESERVATION_MAP_OFFSET_FIELD) else {
        warn!("invalid FDT memory reservation map offset");
        return;
    };
    let Some(structure_offset) = read_offset(STRUCTURE_BLOCK_OFFSET_FIELD) else {
        warn!("invalid FDT structure block offset");
        return;
    };

    // Parse this directly instead of using `Fdt::memory_reservations()`: the
    // pinned fdt implementation slices at `off_mem_rsvmap` without first
    // checking that the offset is within the DTB buffer.
    if offset < FDT_HEADER_SIZE
        || offset % size_of::<u64>() != 0
        || structure_offset > data.len()
        || offset > structure_offset
    {
        warn!("invalid FDT memory reservation map bounds");
        return;
    }
    let Some(reservations) = data.get(offset..structure_offset) else {
        warn!("invalid FDT memory reservation map bounds");
        return;
    };
    offset = 0;

    loop {
        let Some(end) = offset.checked_add(RESERVATION_ENTRY_SIZE) else {
            warn!("invalid FDT memory reservation map");
            return;
        };
        let Some(entry) = reservations.get(offset..end) else {
            warn!("unterminated FDT memory reservation map");
            return;
        };
        let address = u64::from_be_bytes(entry[..8].try_into().unwrap());
        let size = u64::from_be_bytes(entry[8..].try_into().unwrap());

        if address == 0 && size == 0 {
            return;
        }

        match (usize::try_from(address), usize::try_from(size)) {
            (Ok(address), Ok(size)) if address.checked_add(size).is_some() => {
                if size != 0 {
                    visit(address, size);
                }
            }
            _ => {
                warn!(
                    "unsupported FDT memory reservation 0x{:016x} size 0x{:016x}",
                    address, size
                );
            }
        }

        offset = end;
    }
}

fn reserved_memory_node_is_available(node: FdtNode<'_, '_>) -> bool {
    match node.property("status") {
        None => true,
        Some(status) => matches!(status.as_str(), Some("ok" | "okay")),
    }
}

/// Visit a dynamically declared region whose allocation is nevertheless fully
/// determined by its `alloc-ranges` property.
///
/// A `size` property normally describes a pool that the operating system must
/// allocate at run time, so reserving an arbitrary part of `alloc-ranges` would
/// be wrong. A single range with precisely that size is different: there is
/// only one possible allocation, making it a fixed firmware carve-out in
/// practice. This is used by Amlogic's `linux,secmon` DT nodes.
fn visit_exact_dynamic_reserved_memory_range(
    node: FdtNode<'_, '_>,
    cell_sizes: CellSizes,
    visit: &mut impl FnMut(usize, usize),
) -> bool {
    let Some(size_property) = node.property("size") else {
        return false;
    };
    let Some(size_bytes) = cell_sizes.size_cells.checked_mul(size_of::<u32>()) else {
        warn!("invalid reserved-memory size property for {}", node.name);
        return false;
    };
    if size_property.value.len() != size_bytes {
        warn!("invalid reserved-memory size property for {}", node.name);
        return false;
    }
    let Some(size) = cells_to_usize(size_property.value, cell_sizes.size_cells) else {
        warn!("unsupported reserved-memory size for {}", node.name);
        return false;
    };

    let Some(alloc_ranges) = node.property("alloc-ranges") else {
        return false;
    };
    let Some(stride_cells) = cell_sizes.address_cells.checked_add(cell_sizes.size_cells) else {
        warn!(
            "invalid reserved-memory alloc-ranges property for {}",
            node.name
        );
        return false;
    };
    let Some(stride) = stride_cells.checked_mul(size_of::<u32>()) else {
        warn!(
            "invalid reserved-memory alloc-ranges property for {}",
            node.name
        );
        return false;
    };
    let Some(address_bytes) = cell_sizes.address_cells.checked_mul(size_of::<u32>()) else {
        warn!(
            "invalid reserved-memory alloc-ranges property for {}",
            node.name
        );
        return false;
    };

    // Multiple ranges, or a range larger than `size`, leave the allocation
    // address unspecified and must remain available to a future CMA allocator.
    if stride == 0 || alloc_ranges.value.len() != stride {
        return false;
    }
    let Some(address) = cells_to_usize(
        &alloc_ranges.value[..address_bytes],
        cell_sizes.address_cells,
    ) else {
        warn!(
            "unsupported reserved-memory allocation address for {}",
            node.name
        );
        return false;
    };
    let Some(range_size) =
        cells_to_usize(&alloc_ranges.value[address_bytes..], cell_sizes.size_cells)
    else {
        warn!(
            "unsupported reserved-memory allocation size for {}",
            node.name
        );
        return false;
    };

    if size == 0 || range_size != size || address.checked_add(size).is_none() {
        return false;
    }

    debug!(
        "reserving exact dynamic memory {} 0x{:08x} size 0x{:08x}",
        node.name, address, size
    );
    visit(address, size);
    true
}

/// Remove firmware and device-tree carve-outs from the physical allocator.
///
/// The FDT reservation map and `reg` properties below `/reserved-memory`
/// describe fixed allocations. Dynamic nodes are left for a future CMA
/// allocator, except when a single exact `alloc-ranges` makes their address
/// unambiguous.
fn visit_fixed_reserved_memory_ranges(dt: &Fdt, mut visit: impl FnMut(usize, usize)) {
    visit_fdt_memory_reservations(dt, &mut visit);

    let Some(reserved_memory) = dt.find_node("/reserved-memory") else {
        return;
    };
    let Some(cell_sizes) = explicit_cell_sizes(reserved_memory) else {
        warn!("invalid /reserved-memory cell sizes; ignoring its children");
        return;
    };
    let Some(root) = dt.find_node("/") else {
        warn!("missing root node; ignoring /reserved-memory children");
        return;
    };
    let Some(root_cell_sizes) = explicit_cell_sizes(root) else {
        warn!("invalid root cell sizes; ignoring /reserved-memory children");
        return;
    };
    let valid_cell_sizes = cell_sizes.address_cells == root_cell_sizes.address_cells
        && cell_sizes.size_cells == root_cell_sizes.size_cells;
    let valid_ranges = reserved_memory
        .property("ranges")
        .is_some_and(|ranges| ranges.value.is_empty());

    if !valid_cell_sizes || !valid_ranges {
        warn!("invalid /reserved-memory node format; ignoring its children");
        return;
    }

    for child in reserved_memory.children() {
        if !reserved_memory_node_is_available(child) {
            continue;
        }

        if let Some(regions) = child.property("reg") {
            visit_address_size_pairs(regions, cell_sizes, child.name, &mut visit);
        } else if child.property("size").is_some() {
            if !visit_exact_dynamic_reserved_memory_range(child, cell_sizes, &mut visit) {
                // TODO: register dynamic reserved-memory pools once a CMA allocator exists.
                debug!(
                    "dynamic reserved-memory node {}; ignoring it until allocation is supported",
                    child.name
                );
            }
        } else {
            warn!(
                "reserved-memory node {} has neither reg nor size; ignoring it",
                child.name
            );
        }
    }
}

/// Remove fixed firmware and device-tree carve-outs from the physical allocator.
pub fn register_fixed_reserved_memory_ranges(dt: &Fdt) {
    visit_fixed_reserved_memory_ranges(dt, |address, size| {
        register_memory_region(address, size, BootloaderMemoryKind::Reserved);
    });
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

    if let Some(soc_node) = dt.find_node("/soc") {
        if let Some(reg) = soc_node.ranges() {
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
        } else {
            warn!("devicetree /soc has no ranges");
        }

        // also add direct /soc children because they might not be shown in
        // ranges (an identity-mapped bus may have empty ranges)
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
    } else {
        warn!("failed to find /soc in devicetree");
    }

    // The selected console may be below a nested bus whose own `reg` range
    // does not cover all children. Register the exact translated range so it
    // remains mapped after the boot-time identity map is replaced.
    if let Some((address, size, _, _, _)) = diag_uart_range(dt) {
        debug!(
            "diagnostic UART 0x{:08x} size 0x{:08x}",
            address.data(),
            size
        );
        register_memory_region(address.data(), size, BootloaderMemoryKind::Device);
    }

    // Interrupt controllers are not required to live below /soc. Some
    // devicetrees place the primary GIC directly below the root node, so its
    // register ranges would otherwise be absent from the kernel physmap.
    if let Some(root) = dt.find_node("/") {
        for controller in root
            .children()
            .filter(|node| node.property("interrupt-controller").is_some())
        {
            let Some(regions) = controller.reg() else {
                continue;
            };
            for region in regions {
                let Some(size) = region.size else {
                    continue;
                };
                let Some(address) = translate_mmio_address(dt, &controller, &region) else {
                    continue;
                };
                debug!(
                    "root interrupt controller {} 0x{:08x} size 0x{:08x}",
                    controller.name, address, size
                );
                register_memory_region(address, size, BootloaderMemoryKind::Device);
            }
        }
    }
}

fn same_node(left: FdtNode<'_, '_>, right: FdtNode<'_, '_>) -> bool {
    if left.name != right.name {
        return false;
    }
    // FdtNode is reconstructed while walking the tree and has no identity
    // operation. A property's value is a slice into the original DTB, so equal
    // `reg` slice pointers identify the same node occurrence without relying
    // on names that may repeat below different buses.
    match (left.property("reg"), right.property("reg")) {
        (Some(left_reg), Some(right_reg)) => core::ptr::eq(left_reg.value, right_reg.value),
        _ => false,
    }
}

fn translate_bus_address(bus: FdtNode<'_, '_>, address: usize, size: usize) -> Option<usize> {
    let ranges_property = bus.property("ranges")?;
    if ranges_property.value.is_empty() {
        return Some(address);
    }

    let last_offset = size.saturating_sub(1);
    let ranges = bus.ranges()?;
    for range in ranges {
        let Some(offset) = address.checked_sub(range.child_bus_address) else {
            continue;
        };
        if offset < range.size && last_offset < range.size - offset {
            return range.parent_bus_address.checked_add(offset);
        }
    }
    None
}

fn translate_from_subtree(
    bus_or_device: FdtNode<'_, '_>,
    target: FdtNode<'_, '_>,
    address: usize,
    size: usize,
) -> Option<usize> {
    if same_node(bus_or_device, target) {
        return Some(address);
    }

    for child in bus_or_device.children() {
        if let Some(child_address) = translate_from_subtree(child, target, address, size) {
            // `bus_or_device` is the bus parent of the subtree that matched.
            return translate_bus_address(bus_or_device, child_address, size);
        }
    }
    None
}

/// Translate a device's bus-relative `reg` address through every ancestor's
/// `ranges` property until it reaches the CPU physical address space.
pub fn translate_mmio_address(fdt: &Fdt, device: &FdtNode, region: &MemoryRegion) -> Option<usize> {
    /* DT spec 2.3.8 "ranges":
     * The ranges property provides a means of defining a mapping or translation between
     * the address space of the bus (the child address space) and the address space of the bus
     * node’s parent (the parent address space).
     * If the property is defined with an <empty> value, it specifies that the parent and child
     * address space is identical, and no address translation is required.
     * If the property is not present in a bus node, it is assumed that no mapping exists between
     * children of the node and the parent address space.
     */

    let address = region.starting_address as usize;
    let size = region.size.unwrap_or(1);
    let root = fdt.find_node("/")?;

    // The root is already the CPU address space, so only its children perform
    // translations. This also supports devices that are not under `/soc`.
    for child in root.children() {
        if let Some(translated) = translate_from_subtree(child, *device, address, size) {
            translated.checked_add(size.saturating_sub(1))?;
            return Some(translated);
        }
    }
    None
}

// FIXME return PhysicalAddress
pub fn get_mmio_address(fdt: &Fdt, _device: &FdtNode, region: &MemoryRegion) -> Option<usize> {
    let mut mapped_addr = region.starting_address as usize;
    let size = region.size.unwrap_or(0).saturating_sub(1);
    let last_address = mapped_addr.saturating_add(size);
    if let Some(parent) = fdt.find_node("/soc") {
        let mut ranges = parent.ranges().map(|ranges| ranges.peekable())?;
        if ranges.peek().is_some() {
            let parent_range = ranges.find(|range| {
                range.child_bus_address <= mapped_addr
                    && last_address - range.child_bus_address <= range.size
            })?;
            mapped_addr = parent_range
                .parent_bus_address
                .checked_add(mapped_addr - parent_range.child_bus_address)?;
            let _ = mapped_addr.checked_add(size)?;
        }
    }
    Some(mapped_addr)
}

#[cfg_attr(not(dtb), expect(dead_code))]
pub fn interrupt_parent<'a>(fdt: &'a Fdt, node: &'a FdtNode) -> Option<FdtNode<'a, 'a>> {
    // FIXME traverse device tree up
    node.interrupt_parent()
        .or_else(|| fdt.find_node("/soc").and_then(|soc| soc.interrupt_parent()))
        .or_else(|| fdt.find_node("/").and_then(|node| node.interrupt_parent()))
}

#[cfg(dtb)]
pub fn get_interrupt(fdt: &Fdt, node: &FdtNode, idx: usize) -> Option<IrqCell> {
    let interrupts = node.property("interrupts")?;
    let parent_interrupt_cells = interrupt_parent(fdt, node)?.interrupt_cells()?;
    let mut intr = interrupts
        .value
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&f| u32::from_be_bytes(f))
        .skip(parent_interrupt_cells * idx);
    match parent_interrupt_cells {
        1 => Some(IrqCell::L1(intr.next()?)),
        2 if let Ok([a, b]) = intr.next_chunk() => Some(IrqCell::L2(a, b)),
        3 if let Ok([a, b, c]) = intr.next_chunk() => Some(IrqCell::L3(a, b, c)),
        _ => None,
    }
}

pub fn diag_uart_node<'a>(dtb: &'a Fdt) -> Option<FdtNode<'a, 'a>> {
    Some(dtb.chosen().stdout()?.node())
}

pub fn diag_uart_params<'a>(dtb: &'a Fdt<'a>) -> Option<&'a str> {
    dtb.chosen().stdout()?.params()
}

pub fn diag_uart_range<'a>(dtb: &'a Fdt) -> Option<(PhysicalAddress, usize, bool, bool, &'a str)> {
    let uart_node = diag_uart_node(dtb)?;
    let skip_init = uart_node.property("skip-init").is_some();
    let cts_event_walkaround = uart_node.property("cts-event-walkaround").is_some();
    let compatible = uart_node
        .property("compatible")
        .and_then(NodeProperty::as_str)?;

    let mut reg = uart_node.reg()?;
    let memory = reg.next()?;
    let address = translate_mmio_address(dtb, &uart_node, &memory)?;

    Some((
        PhysicalAddress::new(address),
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

#[cfg(test)]
mod tests {
    use super::{
        explicit_cell_sizes, translate_mmio_address, visit_address_size_pairs,
        visit_fdt_memory_reservations, visit_fixed_reserved_memory_ranges,
    };
    use fdt::{
        node::{CellSizes, NodeProperty},
        Fdt,
    };

    static MMIO_DTB: &[u8] = include_bytes!("testdata/mmio.dtb");
    static INVALID_RESERVED_MEMORY_DTB: &[u8] =
        include_bytes!("testdata/invalid-reserved-memory.dtb");

    fn translated(path: &str) -> Option<usize> {
        let fdt = Fdt::new(MMIO_DTB).unwrap();
        let node = fdt.find_node(path).unwrap();
        let region = node.reg().unwrap().next().unwrap();
        translate_mmio_address(&fdt, &node, &region)
    }

    #[test]
    fn translates_uart_through_nested_and_empty_ranges() {
        assert_eq!(translated("/soc/bus@1000/serial@200"), Some(0x1200));
    }

    #[test]
    fn accepts_region_ending_exactly_at_range_boundary() {
        assert_eq!(translated("/soc/bus@1000/device@ff0"), Some(0x1ff0));
    }

    #[test]
    fn rejects_region_crossing_range_boundary() {
        assert_eq!(translated("/soc/bus@1000/device@ff1"), None);
    }

    #[test]
    fn empty_ranges_is_identity_mapping() {
        assert_eq!(translated("/identity-bus/device@3000"), Some(0x3000));
    }

    #[test]
    fn visits_fdt_and_static_reserved_memory_ranges() {
        let fdt = Fdt::new(MMIO_DTB).unwrap();
        let mut ranges = Vec::new();

        visit_fixed_reserved_memory_ranges(&fdt, |address, size| ranges.push((address, size)));

        assert_eq!(
            ranges,
            vec![
                (0x1000, 0x100),
                (0x2000, 0x100),
                (0x3000, 0x80),
                (0x4000, 0x40),
                (0x6000, 0x200),
            ]
        );
    }

    #[test]
    fn rejects_invalid_fdt_reservation_map_bounds() {
        const RESERVATION_MAP_OFFSET_FIELD: usize = 16;

        for offset in [0, u32::MAX.wrapping_sub(7)] {
            let mut data = MMIO_DTB.to_vec();
            data[RESERVATION_MAP_OFFSET_FIELD..RESERVATION_MAP_OFFSET_FIELD + 4]
                .copy_from_slice(&offset.to_be_bytes());
            let fdt = Fdt::new(&data).unwrap();
            let mut ranges = Vec::new();

            visit_fdt_memory_reservations(&fdt, &mut |address, size| {
                ranges.push((address, size));
            });

            assert!(ranges.is_empty());
        }
    }

    #[test]
    fn rejects_an_unterminated_fdt_reservation_map() {
        const STRUCTURE_BLOCK_OFFSET_FIELD: usize = 8;
        const RESERVATION_MAP_OFFSET_FIELD: usize = 16;

        let mut data = MMIO_DTB.to_vec();
        let off_mem_rsvmap = u32::from_be_bytes(
            data[RESERVATION_MAP_OFFSET_FIELD..RESERVATION_MAP_OFFSET_FIELD + 4]
                .try_into()
                .unwrap(),
        );
        // Point off_dt_struct one entry past off_mem_rsvmap, cutting the
        // reservation map off before its terminating {0, 0} entry.
        let truncated_structure_offset = off_mem_rsvmap + 16;
        data[STRUCTURE_BLOCK_OFFSET_FIELD..STRUCTURE_BLOCK_OFFSET_FIELD + 4]
            .copy_from_slice(&truncated_structure_offset.to_be_bytes());
        let fdt = Fdt::new(&data).unwrap();
        let mut ranges = Vec::new();

        visit_fdt_memory_reservations(&fdt, &mut |address, size| ranges.push((address, size)));

        // The one real entry that fit before the truncation is still
        // reported; parsing stops instead of reading past the map.
        assert_eq!(ranges, vec![(0x1000, 0x100)]);
    }

    #[test]
    fn parses_32_and_64_bit_address_size_pairs() {
        let cells32 = CellSizes {
            address_cells: 1,
            size_cells: 1,
        };
        let cells64 = CellSizes {
            address_cells: 2,
            size_cells: 2,
        };
        let property32 = NodeProperty {
            name: "reg",
            value: &[0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00],
        };
        let property64 = NodeProperty {
            name: "reg",
            value: &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00,
            ],
        };
        let mut ranges = Vec::new();

        visit_address_size_pairs(property32, cells32, "test32", &mut |address, size| {
            ranges.push((address, size));
        });
        visit_address_size_pairs(property64, cells64, "test64", &mut |address, size| {
            ranges.push((address, size));
        });

        assert_eq!(ranges, vec![(0x2000, 0x100), (0x3000, 0x200)]);
    }

    #[test]
    fn rejects_a_partial_address_size_pair() {
        let property = NodeProperty {
            name: "reg",
            value: &[0; 12],
        };
        let mut ranges = Vec::new();

        visit_address_size_pairs(
            property,
            CellSizes {
                address_cells: 2,
                size_cells: 2,
            },
            "partial",
            &mut |address, size| ranges.push((address, size)),
        );

        assert!(ranges.is_empty());
    }

    #[test]
    fn rejects_an_overflowing_address_size_pair() {
        let address = usize::MAX - 0x10;
        let size = 0x20_usize;
        let mut value = Vec::new();
        let cell_sizes = if usize::BITS == 64 {
            value.extend_from_slice(&(address as u64).to_be_bytes());
            value.extend_from_slice(&(size as u64).to_be_bytes());
            CellSizes {
                address_cells: 2,
                size_cells: 2,
            }
        } else {
            value.extend_from_slice(&(address as u32).to_be_bytes());
            value.extend_from_slice(&(size as u32).to_be_bytes());
            CellSizes {
                address_cells: 1,
                size_cells: 1,
            }
        };
        let property = NodeProperty {
            name: "reg",
            value: &value,
        };
        let mut ranges = Vec::new();

        visit_address_size_pairs(property, cell_sizes, "overflow", &mut |address, size| {
            ranges.push((address, size));
        });

        assert!(ranges.is_empty());
    }

    #[test]
    fn explicit_cell_sizes_is_none_when_properties_are_missing() {
        let fdt = Fdt::new(MMIO_DTB).unwrap();
        let node = fdt.find_node("/reserved-memory/firmware@2000").unwrap();

        assert!(explicit_cell_sizes(node).is_none());
    }

    #[test]
    fn ignores_reserved_memory_children_with_nonempty_ranges() {
        let fdt = Fdt::new(INVALID_RESERVED_MEMORY_DTB).unwrap();
        let mut ranges = Vec::new();

        visit_fixed_reserved_memory_ranges(&fdt, |address, size| ranges.push((address, size)));

        assert_eq!(ranges, vec![(0x1000, 0x100)]);
    }
}
