use byteorder::{ByteOrder, BE};
use core::slice;
use fdt::{node::NodeProperty, Fdt};
use log::debug;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct MemoryArea {
    pub base_addr: u64,
    pub length: u64,
    pub _type: u32,
    pub acpi: u32,
}

pub static mut MEMORY_MAP: [MemoryArea; 512] = [MemoryArea {
    base_addr: 0,
    length: 0,
    _type: 0,
    acpi: 0,
}; 512];

pub fn travel_interrupt_ctrl(fdt: &Fdt) {
    let root_intr_parent = fdt
        .root()
        .property("interrupt-parent")
        .and_then(NodeProperty::as_usize)
        .unwrap();
    debug!("root parent = 0x{:08x}", root_intr_parent);
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
fn memory_ranges(dt: &Fdt, ranges: &mut [(usize, usize); 10]) -> usize {
    let mut index = 0;
    for chunk in dt.memory().regions() {
        if index >= ranges.len() || chunk.size.is_none() {
            break;
        }
        ranges[index] = (chunk.starting_address as usize, chunk.size.unwrap());
        index += 1;
    }
    index
}

fn dev_memory_ranges(dt: &Fdt, ranges: &mut [(usize, usize); 10]) -> usize {
    // work around for qemu-arm64
    // dev mem: 128MB - 1GB, see https://github.com/qemu/qemu/blob/master/hw/arm/virt.c for details
    let root_node = dt.root();
    let is_qemu_virt = root_node.model().contains("linux,dummy-virt");

    if is_qemu_virt {
        ranges[0] = (0x08000000, 0x08000000);
        ranges[1] = (0x10000000, 0x30000000);
        return 2;
    }

    let soc_node = dt.find_node("/soc").unwrap();
    let reg = soc_node.ranges().unwrap();

    let mut index = 0;
    for chunk in reg {
        if index >= ranges.len() {
            break;
        }
        debug!(
            "dev mem 0x{:08x} 0x{:08x} 0x{:08x} 0x{:08x}",
            chunk.child_bus_address_hi,
            chunk.child_bus_address,
            chunk.parent_bus_address,
            chunk.size
        );

        ranges[index] = (chunk.parent_bus_address, chunk.size);
        index += 1;
    }
    index
}

pub fn diag_uart_range(dtb_base: usize, dtb_size: usize) -> Option<(usize, usize, bool, bool)> {
    let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
    let dt = Fdt::new(data).unwrap();

    let stdout_path = dt.chosen().stdout().unwrap();
    let uart_node = stdout_path.node();
    let skip_init = uart_node.property("skip-init").is_some();
    let cts_event_walkaround = uart_node.property("cts-event-walkaround").is_some();

    let mut reg = uart_node.reg().unwrap();
    let memory = reg.nth(0).unwrap();

    Some((
        memory.starting_address as usize,
        memory.size.unwrap(),
        skip_init,
        cts_event_walkaround,
    ))
}

#[allow(unused)]
pub fn fill_env_data(dtb_base: usize, dtb_size: usize, env_base: usize) -> usize {
    let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
    let dt = Fdt::new(data).unwrap();

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

pub fn fill_memory_map(dtb_base: usize, dtb_size: usize) {
    let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
    let dt = Fdt::new(data).unwrap();

    let mut ranges: [(usize, usize); 10] = [(0, 0); 10];

    //in uefi boot mode, ignore memory node, just read the device memory range
    //let nranges = memory_ranges(&dt, &mut ranges);
    let nranges = dev_memory_ranges(&dt, &mut ranges);

    for index in 0..nranges {
        let (base, size) = ranges[index];
        unsafe {
            MEMORY_MAP[index] = MemoryArea {
                base_addr: base as u64,
                length: size as u64,
                _type: 2,
                acpi: 0,
            };
        }
    }
}
