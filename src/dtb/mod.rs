#[cfg(dtb)]
pub mod irqchip;
pub mod serial;

#[cfg(dtb)]
use crate::dtb::irqchip::IrqCell;
use crate::startup::memory::{register_memory_region, BootloaderMemoryKind};
use core::slice;
#[cfg(dtb)]
use fdt::properties::interrupts::Interrupts;
use fdt::{
    properties::{
        cells::{AddressCells, CellSizes, SizeCells},
        interrupts::{InterruptCells, InterruptController, InterruptParent},
        ranges::Ranges,
        reg::{Reg, RegEntry},
        Compatible, PHandle, Status,
    },
    FdtError,
};
use rmm::PhysicalAddress;
use spin::once::Once;

/// Represents the in-memory DTB (DeviceTree) binary.
pub static DTB_BINARY: Once<&'static [u8]> = Once::new();

pub fn global_dtb() -> Option<Result<Fdt<'static>, FdtError>> {
    let dtb = *DTB_BINARY.get()?;
    let data32 = unsafe { slice::from_raw_parts(dtb.as_ptr() as *const u32, dtb.len() / 4) };
    Some(fdt::Fdt::new(data32))
}

type FdtParser<'a> = (
    fdt::parsing::aligned::AlignedParser<'a>,
    fdt::parsing::Panic,
);
pub(crate) type Fdt<'a> = fdt::Fdt<'a, FdtParser<'a>>;
pub(crate) type FdtNode<'a> = fdt::nodes::Node<'a, FdtParser<'a>>;

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
        .find_node("/")
        .unwrap()
        .property::<InterruptParent>()
        .and_then(|int_parent| int_parent.property::<PHandle>())
    {
        debug!("root parent = 0x{:08x}", root_intr_parent.as_u32());
    }
    for (_id, node) in fdt.all_nodes() {
        if node.property::<InterruptController>().is_some() {
            let Some(compatible) = node.property::<Compatible>() else {
                continue;
            };
            let compatible = compatible.first();
            let Some(phandle) = node.property::<PHandle>() else {
                continue;
            };
            let phandle = phandle.as_u32();
            if let Some(intr_cells) = node.property::<InterruptCells>() {
                let intr = node
                    .property::<InterruptParent>()
                    .and_then(|int_parent| int_parent.property::<PHandle>());
                let intr_data = node.raw_property("interrupts");

                debug!(
                    "{}, compatible = {}, #interrupt-cells = 0x{:08x}, phandle = 0x{:08x}",
                    node.name(),
                    compatible,
                    intr_cells.0,
                    phandle
                );
                if let Some(intr) = intr {
                    if let Some(intr_data) = intr_data {
                        debug!("interrupt-parent = 0x{:08x}", intr.as_u32());
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

fn explicit_cell_sizes(node: FdtNode<'_>) -> Option<CellSizes> {
    Some(CellSizes {
        address_cells: node.property::<AddressCells>()?.0,
        size_cells: node.property::<SizeCells>()?.0,
    })
}

fn visit_fdt_memory_reservations(dt: &Fdt, raw_data: &[u8], visit: &mut impl FnMut(usize, usize)) {
    const FDT_HEADER_SIZE: usize = 10 * size_of::<u32>();
    const STRUCTURE_BLOCK_OFFSET_FIELD: usize = 8;
    const RESERVATION_MAP_OFFSET_FIELD: usize = 16;
    const RESERVATION_ENTRY_SIZE: usize = 2 * size_of::<u64>();

    let data = &raw_data[..dt.total_size()];
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

fn reserved_memory_node_is_available(node: FdtNode<'_>) -> bool {
    matches!(node.property::<Status>(), None | Some(Status::OKAY))
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
    node: FdtNode<'_>,
    cell_sizes: CellSizes,
    visit: &mut impl FnMut(usize, usize),
) -> bool {
    let Some(size_property) = node.raw_property("size") else {
        return false;
    };
    let Some(size_bytes) = cell_sizes.size_cells.checked_mul(size_of::<u32>()) else {
        warn!("invalid reserved-memory size property for {}", node.name());
        return false;
    };
    if size_property.value.len() != size_bytes {
        warn!("invalid reserved-memory size property for {}", node.name());
        return false;
    }
    let Some(size) = cells_to_usize(size_property.value, cell_sizes.size_cells) else {
        warn!("unsupported reserved-memory size for {}", node.name());
        return false;
    };

    let Some(alloc_ranges) = node.raw_property("alloc-ranges") else {
        return false;
    };
    let Some(stride_cells) = cell_sizes.address_cells.checked_add(cell_sizes.size_cells) else {
        warn!(
            "invalid reserved-memory alloc-ranges property for {}",
            node.name()
        );
        return false;
    };
    let Some(stride) = stride_cells.checked_mul(size_of::<u32>()) else {
        warn!(
            "invalid reserved-memory alloc-ranges property for {}",
            node.name()
        );
        return false;
    };
    let Some(address_bytes) = cell_sizes.address_cells.checked_mul(size_of::<u32>()) else {
        warn!(
            "invalid reserved-memory alloc-ranges property for {}",
            node.name()
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
            node.name()
        );
        return false;
    };
    let Some(range_size) =
        cells_to_usize(&alloc_ranges.value[address_bytes..], cell_sizes.size_cells)
    else {
        warn!(
            "unsupported reserved-memory allocation size for {}",
            node.name()
        );
        return false;
    };

    if size == 0 || range_size != size || address.checked_add(size).is_none() {
        return false;
    }

    debug!(
        "reserving exact dynamic memory {} 0x{:08x} size 0x{:08x}",
        node.name(),
        address,
        size
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
fn visit_fixed_reserved_memory_ranges(
    dt: &Fdt,
    raw_data: &[u8],
    mut visit: impl FnMut(usize, usize),
) {
    visit_fdt_memory_reservations(dt, raw_data, &mut visit);

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
        .property::<Ranges>()
        .is_some_and(|ranges| ranges.iter::<usize, usize, usize>().next().is_none());

    if !valid_cell_sizes || !valid_ranges {
        warn!("invalid /reserved-memory node format; ignoring its children");
        return;
    }

    for child in reserved_memory.children() {
        if !reserved_memory_node_is_available(child) {
            continue;
        }

        if let Some(regions) = child.property::<Reg>() {
            for reg in regions.iter::<usize, usize>() {
                visit(reg.unwrap().address, reg.unwrap().len);
            }
        } else if child.raw_property("size").is_some() {
            if !visit_exact_dynamic_reserved_memory_range(child, cell_sizes, &mut visit) {
                // TODO: register dynamic reserved-memory pools once a CMA allocator exists.
                debug!(
                    "dynamic reserved-memory node {}; ignoring it until allocation is supported",
                    child.name()
                );
            }
        } else {
            warn!(
                "reserved-memory node {} has neither reg nor size; ignoring it",
                child.name()
            );
        }
    }
}

/// Remove fixed firmware and device-tree carve-outs from the physical allocator.
pub fn register_fixed_reserved_memory_ranges(dt: &Fdt, raw_data: &[u8]) {
    visit_fixed_reserved_memory_ranges(dt, raw_data, |address, size| {
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
            for chunk in reg.iter::<usize, usize, usize>() {
                let Ok(chunk) = chunk else {
                    continue;
                };
                debug!(
                    "dev mem 0x{:08x} 0x{:08x} 0x{:08x}",
                    chunk.child_bus_address, chunk.parent_bus_address, chunk.len,
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
                for entry in reg.iter::<usize, usize>() {
                    let Ok(entry) = entry else {
                        continue;
                    };
                    let addr = entry.address;
                    let len = entry.len;
                    if let Some(mapped_addr) = get_mmio_address(dt, &device, &entry) {
                        debug!(
                            "soc device {} 0x{:08x} -> 0x{:08x} len 0x{:08x}",
                            device.name(),
                            addr,
                            mapped_addr,
                            len
                        );
                        register_memory_region(mapped_addr, len, BootloaderMemoryKind::Device);
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
            .iter()
            .filter(|node| node.property::<InterruptController>().is_some())
        {
            let Some(regions) = controller.reg() else {
                continue;
            };
            for region in regions.iter::<usize, usize>() {
                let Ok(region) = region else {
                    continue;
                };
                let Some(address) = translate_mmio_address(dt, &controller, &region) else {
                    continue;
                };
                let len = region.len;
                debug!(
                    "root interrupt controller {} 0x{:08x} len 0x{:08x}",
                    controller.name(),
                    address,
                    len
                );
                register_memory_region(address, len, BootloaderMemoryKind::Device);
            }
        }
    }
}

fn translate_bus_address(bus: FdtNode<'_>, address: usize, size: usize) -> Option<usize> {
    let ranges = bus.ranges()?;
    if ranges.iter::<usize, usize, usize>().next().is_none() {
        return Some(address);
    }

    let last_offset = size.saturating_sub(1);
    for range in ranges.iter::<usize, usize, usize>() {
        let range = range.ok()?;
        let Some(offset) = address.checked_sub(range.child_bus_address) else {
            continue;
        };
        if offset < range.len && last_offset < range.len - offset {
            return range.parent_bus_address.checked_add(offset);
        }
    }
    None
}

fn translate_from_subtree(
    bus_or_device: FdtNode<'_>,
    target: FdtNode<'_>,
    address: usize,
    size: usize,
) -> Option<usize> {
    if bus_or_device.id() == target.id() {
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
pub fn translate_mmio_address(
    fdt: &Fdt,
    device: &FdtNode,
    region: &RegEntry<usize, usize>,
) -> Option<usize> {
    /* DT spec 2.3.8 "ranges":
     * The ranges property provides a means of defining a mapping or translation between
     * the address space of the bus (the child address space) and the address space of the bus
     * node’s parent (the parent address space).
     * If the property is defined with an <empty> value, it specifies that the parent and child
     * address space is identical, and no address translation is required.
     * If the property is not present in a bus node, it is assumed that no mapping exists between
     * children of the node and the parent address space.
     */

    let address = region.address;
    let len = region.len;
    let root = fdt.find_node("/")?;

    // The root is already the CPU address space, so only its children perform
    // translations. This also supports devices that are not under `/soc`.
    for child in root.children() {
        if let Some(translated) = translate_from_subtree(child, *device, address, len) {
            translated.checked_add(len.saturating_sub(1))?;
            return Some(translated);
        }
    }
    None
}

// FIXME return PhysicalAddress
pub fn get_mmio_address(
    fdt: &Fdt,
    _device: &FdtNode,
    region: &RegEntry<usize, usize>,
) -> Option<usize> {
    let mut mapped_addr = region.address;
    let len = region.len.saturating_sub(1);
    let last_address = mapped_addr.saturating_add(len);
    if let Some(parent) = fdt.find_node("/soc") {
        let mut ranges = parent
            .ranges()
            .map(|ranges| ranges.iter::<usize, usize, usize>())?
            .map(|range| range.unwrap())
            .peekable();
        if ranges.peek().is_some() {
            let parent_range = ranges.find(|range| {
                range.child_bus_address <= mapped_addr
                    && last_address - range.child_bus_address <= range.len
            })?;
            mapped_addr = parent_range
                .parent_bus_address
                .checked_add(mapped_addr - parent_range.child_bus_address)?;
            let _ = mapped_addr.checked_add(len)?;
        }
    }
    Some(mapped_addr)
}

#[cfg_attr(not(dtb), expect(dead_code))]
pub fn interrupt_parent<'a>(fdt: &Fdt<'a>, node: FdtNode<'a>) -> Option<FdtNode<'a>> {
    // FIXME traverse device tree up
    node.property::<InterruptParent>()
        .or_else(|| {
            fdt.find_node("/soc")
                .and_then(|soc| soc.property::<InterruptParent>())
        })
        .or_else(|| {
            fdt.find_node("/")
                .and_then(|node| node.property::<InterruptParent>())
        })
        .map(|parent| (*parent).clone())
}

#[cfg(dtb)]
pub fn get_interrupt(node: &FdtNode, idx: usize) -> Option<IrqCell> {
    let interrupts = node.property::<Interrupts>()?;
    match interrupts {
        Interrupts::Legacy(interrupts) => interrupts
            .iter()
            .nth(idx)
            .and_then(IrqCell::from_interrupt_specifier),
        Interrupts::Extended(interrupts) => interrupts.iter().nth(idx).and_then(|interrupt| {
            IrqCell::from_interrupt_specifier(interrupt.interrupt_specifier())
        }),
    }
}

pub fn diag_uart_node<'a>(dtb: &Fdt<'a>) -> Option<FdtNode<'a>> {
    Some(dtb.root().chosen().stdout()?.node)
}

pub fn diag_uart_params<'a>(dtb: &Fdt<'a>) -> Option<&'a str> {
    dtb.root().chosen().stdout()?.params
}

pub fn diag_uart_range<'a>(
    dtb: &Fdt<'a>,
) -> Option<(PhysicalAddress, usize, bool, bool, Compatible<'a>)> {
    let uart_node = diag_uart_node(dtb)?;
    let skip_init = uart_node.raw_property("skip-init").is_some();
    let cts_event_walkaround = uart_node.raw_property("cts-event-walkaround").is_some();
    let compatible = uart_node.property::<Compatible>()?;

    let memory = uart_node.reg()?.iter::<usize, usize>().next()?.ok()?;
    let address = translate_mmio_address(dtb, &uart_node, &memory)?;

    Some((
        PhysicalAddress::new(address),
        memory.len,
        skip_init,
        cts_event_walkaround,
        compatible,
    ))
}

#[allow(unused)]
pub fn fill_env_data(dt: &Fdt, env_base: usize) -> usize {
    if let Some(bootargs) = dt.root().chosen().bootargs() {
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
        explicit_cell_sizes, translate_mmio_address, visit_fdt_memory_reservations,
        visit_fixed_reserved_memory_ranges, Fdt,
    };

    #[repr(C, align(4))]
    #[derive(Copy, Clone)]
    struct AlignedDtb<const N: usize>([u8; N]);

    impl<const N: usize> AlignedDtb<N> {
        fn fdt(&self) -> Fdt<'_> {
            unsafe {
                Fdt::new(std::slice::from_raw_parts(
                    (&raw const self.0) as *const u32,
                    N.div_ceil(4), // FIXME this is UB, but necessary: https://github.com/repnop/fdt/issues/64
                ))
                .unwrap()
            }
        }
    }

    static MMIO_DTB: &AlignedDtb<1190> = &AlignedDtb(*include_bytes!("testdata/mmio.dtb"));
    static INVALID_RESERVED_MEMORY_DTB: &AlignedDtb<302> =
        &AlignedDtb(*include_bytes!("testdata/invalid-reserved-memory.dtb"));

    fn translated(path: &str) -> Option<usize> {
        let fdt = MMIO_DTB.fdt();
        let node = fdt.find_node(path).unwrap();
        let region = node
            .reg()
            .unwrap()
            .iter::<usize, usize>()
            .next()
            .unwrap()
            .unwrap();
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
        let fdt = MMIO_DTB.fdt();
        let mut ranges = Vec::new();

        visit_fixed_reserved_memory_ranges(&fdt, &MMIO_DTB.0, |address, size| {
            ranges.push((address, size))
        });

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
            let mut data = *MMIO_DTB;
            data.0[RESERVATION_MAP_OFFSET_FIELD..RESERVATION_MAP_OFFSET_FIELD + 4]
                .copy_from_slice(&offset.to_be_bytes());
            let fdt = data.fdt();
            let mut ranges = Vec::new();

            visit_fdt_memory_reservations(&fdt, &data.0, &mut |address, size| {
                ranges.push((address, size));
            });

            assert!(ranges.is_empty());
        }
    }

    #[test]
    fn rejects_an_unterminated_fdt_reservation_map() {
        const STRUCTURE_BLOCK_OFFSET_FIELD: usize = 8;
        const RESERVATION_MAP_OFFSET_FIELD: usize = 16;

        let mut data = *MMIO_DTB;
        let off_mem_rsvmap = u32::from_be_bytes(
            data.0[RESERVATION_MAP_OFFSET_FIELD..RESERVATION_MAP_OFFSET_FIELD + 4]
                .try_into()
                .unwrap(),
        );
        // Point off_dt_struct one entry past off_mem_rsvmap, cutting the
        // reservation map off before its terminating {0, 0} entry.
        let truncated_structure_offset = off_mem_rsvmap + 16;
        data.0[STRUCTURE_BLOCK_OFFSET_FIELD..STRUCTURE_BLOCK_OFFSET_FIELD + 4]
            .copy_from_slice(&truncated_structure_offset.to_be_bytes());
        let fdt = data.fdt();
        let mut ranges = Vec::new();

        visit_fdt_memory_reservations(&fdt, &data.0, &mut |address, size| {
            ranges.push((address, size))
        });

        // The one real entry that fit before the truncation is still
        // reported; parsing stops instead of reading past the map.
        assert_eq!(ranges, vec![(0x1000, 0x100)]);
    }

    #[test]
    fn explicit_cell_sizes_is_none_when_properties_are_missing() {
        let fdt = MMIO_DTB.fdt();
        let node = fdt.find_node("/reserved-memory/firmware@2000").unwrap();

        assert!(explicit_cell_sizes(node).is_none());
    }

    #[test]
    fn ignores_reserved_memory_children_with_nonempty_ranges() {
        let fdt = INVALID_RESERVED_MEMORY_DTB.fdt();
        let mut ranges = Vec::new();

        visit_fixed_reserved_memory_ranges(
            &fdt,
            &INVALID_RESERVED_MEMORY_DTB.0,
            |address, size| ranges.push((address, size)),
        );

        assert_eq!(ranges, vec![(0x1000, 0x100)]);
    }
}
