extern crate fdt;
extern crate byteorder;

use alloc::vec::Vec;
use fdt::Node;
use core::slice;
use crate::memory::MemoryArea;
use self::byteorder::{ByteOrder, BE};

pub static mut MEMORY_MAP: [MemoryArea; 512] = [MemoryArea {
    base_addr: 0,
    length: 0,
    _type: 0,
    acpi: 0,
}; 512];

pub fn root_cell_sz(dt: &fdt::DeviceTree) -> Option<(u32, u32)> {
    let root_node = dt.nodes().nth(0).unwrap();
    let address_cells = root_node.properties().find(|p| p.name.contains("#address-cells")).unwrap();
    let size_cells = root_node.properties().find(|p| p.name.contains("#size-cells")).unwrap();

    Some((BE::read_u32(&size_cells.data), BE::read_u32(&size_cells.data)))
}

pub fn travel_interrupt_ctrl(fdt: &fdt::DeviceTree) {
    let root_node = fdt.nodes().nth(0).unwrap();
    let intr = root_node.properties().find(|p| p.name.contains("interrupt-parent")).unwrap();

    let root_intr_parent = BE::read_u32(&intr.data);
    println!("root parent = 0x{:08x}", root_intr_parent);
    for node in fdt.nodes() {
        if node.properties().find(|p| p.name.contains("interrupt-controller")).is_some() {
            let compatible = node.properties().find(|p| p.name.contains("compatible")).unwrap();
            let phandle = node.properties().find(|p| p.name.contains("phandle")).unwrap();
            let intr_cells = node.properties().find(|p| p.name.contains("#interrupt-cells")).unwrap();
            let _intr = node.properties().find(|p| p.name.contains("interrupt-parent"));
            let _intr_data = node.properties().find(|p| p.name.contains("interrupts"));

            let s = core::str::from_utf8(compatible.data).unwrap();
            println!("{}, compatible = {}, #interrupt-cells = 0x{:08x}, phandle = 0x{:08x}", node.name, s, BE::read_u32(intr_cells.data),
                     BE::read_u32(phandle.data));
            if let Some(intr) = _intr {
                if let Some(intr_data) = _intr_data {
                    println!("interrupt-parent = 0x{:08x}", BE::read_u32(intr.data));
                    println!("interrupts begin:");
                    for chunk in intr_data.data.chunks(4) {
                        print!("0x{:08x}, ", BE::read_u32(chunk));
                    }
                    println!("interrupts end");
                }
            }
        }
    }
}

fn memory_ranges(dt: &fdt::DeviceTree, address_cells: usize, size_cells: usize, ranges: &mut [(usize, usize); 10]) -> usize {

    let (memory_node, _memory_cells) = dt.find_node("/memory").unwrap();
    let reg = memory_node.properties().find(|p| p.name.contains("reg")).unwrap();
    let chunk_sz = (address_cells + size_cells) * 4;
    let chunk_count = (reg.data.len() / chunk_sz);
    let mut index = 0;
    for chunk in reg.data.chunks(chunk_sz as usize) {
        if index == chunk_count {
            return index;
        }
        let (base, size) = chunk.split_at((address_cells * 4) as usize);
        let mut b = 0;
        for base_chunk in base.rchunks(4) {
            b += BE::read_u32(base_chunk);
        }
        let mut s = 0;
        for sz_chunk in size.rchunks(4) {
            s += BE::read_u32(sz_chunk);
        }
        ranges[index] = (b as usize, s as usize);
        index += 1;
    }
    index
}

fn dev_memory_ranges(dt: &fdt::DeviceTree, address_cells: usize, size_cells: usize, ranges: &mut [(usize, usize); 10]) -> usize {

    //work around for qemu-arm64
    // dev mem: 128MB - 1GB, see https://github.com/qemu/qemu/blob/master/hw/arm/virt.c for details
    let root_node = dt.nodes().nth(0).unwrap();
    let model = root_node.properties().find(|p| p.name.contains("model")).unwrap();
    let model_str = core::str::from_utf8(model.data).unwrap();
    if model_str.contains("linux,dummy-virt") {
        ranges[0] = (0x08000000, 0x08000000);
        ranges[1] = (0x10000000, 0x30000000);
        return 2;
    }

    let (memory_node, _memory_cells) = dt.find_node("/soc").unwrap();
    let reg = memory_node.properties().find(|p| p.name.contains("ranges")).unwrap();
    let chunk_sz = (address_cells * 2 + size_cells) * 4;
    let chunk_count = (reg.data.len() / chunk_sz);
    let mut index = 0;
    for chunk in reg.data.chunks(chunk_sz as usize) {
        if index == chunk_count {
            return index;
        }
        let child_bus_addr = {
            if address_cells == 1 {
                BE::read_u32(&chunk[0..4]) as u64
            } else if address_cells == 2 {
                BE::read_u64(&chunk[0..8])
            } else {
                return 0;
            }
        };

        let parent_bus_addr = {
            if address_cells == 1 {
                BE::read_u32(&chunk[4..8]) as u64
            } else if address_cells == 2 {
                BE::read_u64(&chunk[8..16])
            } else {
                return 0;
            }
        };

        let addr_size = {
            if address_cells == 1 {
                BE::read_u32(&chunk[8..12]) as u64
            } else if address_cells == 2 {
                BE::read_u64(&chunk[16..24])
            } else {
                return 0;
            }
        };
        println!("dev mem 0x{:08x} 0x{:08x} 0x{:08x}", child_bus_addr, parent_bus_addr, addr_size);

        ranges[index] = (parent_bus_addr as usize, addr_size as usize);
        index += 1;
    }
    index
}

pub fn diag_uart_range(dtb_base: usize, dtb_size: usize) -> Option<(usize, usize)> {
    let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
    let dt = fdt::DeviceTree::new(data).unwrap();

    let (chosen_node, _chosen_cells) = dt.find_node("/chosen").unwrap();
    let stdout_path = chosen_node.properties().find(|p| p.name.contains("stdout-path")).unwrap();
    let uart_node_name = core::str::from_utf8(stdout_path.data).unwrap()
        .split('/')
        .nth(1)?
        .trim_end();
    let len = uart_node_name.len();
    let uart_node_name = &uart_node_name[0..len-1];
    let uart_node = dt.nodes().find(|n| n.name.contains(uart_node_name)).unwrap();
    let reg = uart_node.properties().find(|p| p.name.contains("reg")).unwrap();

    let (address_cells, size_cells) = root_cell_sz(&dt).unwrap();
    let chunk_sz = (address_cells + size_cells) * 4;
    let (base, size) = reg.data.split_at((address_cells * 4) as usize);
    let mut b = 0;
    for base_chunk in base.rchunks(4) {
        b += BE::read_u32(base_chunk);
    }
    let mut s = 0;
    for sz_chunk in size.rchunks(4) {
        s += BE::read_u32(sz_chunk);
    }
    Some((b as usize, s as usize))
}

fn compatible_node_present<'a>(dt: &fdt::DeviceTree<'a>, compat_string: &str) -> bool {
    for node in dt.nodes() {
        if let Some(compatible) = node.properties().find(|p| p.name.contains("compatible")) {
            let s = core::str::from_utf8(compatible.data).unwrap();
            if s.contains(compat_string) {
                return true;
            }
        }
    }
    false
}

pub fn find_compatible_node<'a>(dt: &'a fdt::DeviceTree<'a>, compat_string: &str) -> Option<Node<'a, 'a>> {
    for node in dt.nodes() {
        if let Some(compatible) = node.properties().find(|p| p.name.contains("compatible")) {
            let s = core::str::from_utf8(compatible.data).unwrap();
            if s.contains(compat_string) {
                return Some(node);
            }
        }
    }
    None
}

pub fn fill_env_data(dtb_base: usize, dtb_size: usize, env_base: usize) -> usize {
    let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
    let dt = fdt::DeviceTree::new(data).unwrap();

    let (chosen_node, _chosen_cells) = dt.find_node("/chosen").unwrap();
    if let Some(bootargs) = chosen_node.properties().find(|p| p.name.contains("bootargs")) {
        let bootargs_len = bootargs.data.len();

        let env_base_slice = unsafe { slice::from_raw_parts_mut(env_base as *mut u8, bootargs_len) };
        env_base_slice[..bootargs_len].clone_from_slice(bootargs.data);

        bootargs_len
    } else {
        0
    }
}

pub fn fill_memory_map(dtb_base: usize, dtb_size: usize) {
    let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
    let dt = fdt::DeviceTree::new(data).unwrap();

    let (address_cells, size_cells) = root_cell_sz(&dt).unwrap();
    let mut ranges: [(usize, usize); 10] = [(0,0); 10];

	//in uefi boot mode, ignore memory node, just read the device memory range 
    //let nranges = memory_ranges(&dt, address_cells as usize, size_cells as usize, &mut ranges);
	let nranges = dev_memory_ranges(&dt, address_cells as usize, size_cells as usize, &mut ranges);

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
