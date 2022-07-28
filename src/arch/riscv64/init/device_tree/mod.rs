extern crate fdt;
extern crate byteorder;

use alloc::vec::Vec;
use core::slice;
use crate::memory::MemoryArea;
use self::byteorder::{ByteOrder, BE};

pub static mut MEMORY_MAP: [MemoryArea; 512] = [MemoryArea {
    base_addr: 0,
    length: 0,
    _type: 0,
    acpi: 0,
}; 512];

fn root_cell_sz(dt: &fdt::DeviceTree) -> Option<(u32, u32)> {
    let root_node = dt.nodes().nth(0).unwrap();
    let address_cells = root_node.properties().find(|p| p.name.contains("#address-cells")).unwrap();
    let size_cells = root_node.properties().find(|p| p.name.contains("#size-cells")).unwrap();

    Some((BE::read_u32(&size_cells.data), BE::read_u32(&size_cells.data)))
}

fn memory_ranges(dt: &fdt::DeviceTree, address_cells: usize, size_cells: usize, ranges: &mut [(usize, usize); 10]) -> usize {

    let memory_node = dt.find_node("/memory").unwrap();
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

pub fn diag_uart_range(dtb_base: usize, dtb_size: usize) -> Option<(usize, usize)> {
    let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
    let dt = fdt::DeviceTree::new(data).unwrap();

    let chosen_node = dt.find_node("/chosen").unwrap();
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

pub fn fill_env_data(dtb_base: usize, dtb_size: usize, env_base: usize) -> usize {
    let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
    let dt = fdt::DeviceTree::new(data).unwrap();

    let chosen_node = dt.find_node("/chosen").unwrap();
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

    let nranges = memory_ranges(&dt, address_cells as usize, size_cells as usize, &mut ranges);

    for index in (0..nranges) {
        let (base, size) = ranges[index];
        unsafe {
            MEMORY_MAP[index] = MemoryArea {
                base_addr: base as u64,
                length: size as u64,
                _type: 1,
                acpi: 0,
            };
        }
    }
}
