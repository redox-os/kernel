use alloc::vec::Vec;
use bitfield::Bit;
use core::fmt::Write;
use rmm::{GIGABYTE, MEGABYTE};
use syscall::{Result, MAX_CPU_COUNT};

use crate::{acpi::find_sdt, numa::MAX_MEM_REGIONS, percpu, sync::CleanLockToken};

pub fn resource(_: &mut CleanLockToken) -> Result<Vec<u8>> {
    if let Some(nodes) = crate::numa::NUMA_NODES.get() {
        let mut string = format!(
            "NUMA nodes: {}\n",
            nodes.iter().filter(|e| e.is_some()).count()
        );
        nodes
            .iter()
            .enumerate()
            .map_while(|e| Some((e.0, e.1.as_ref()?)))
            .for_each(|(node_id, node)| {
                writeln!(&mut string, "Node {}:", node_id).unwrap();
                write!(&mut string, "\tCPUs: ").unwrap();

                for i in 0..MAX_CPU_COUNT as usize {
                    if node.cpus.bit(i) {
                        write!(&mut string, "{} ", i).unwrap();
                    }
                }

                write!(&mut string, "\n\tMemory: ").unwrap();
                if node.mem_size / GIGABYTE < 1 {
                    let mem = node.mem_size as f64 / MEGABYTE as f64;
                    writeln!(&mut string, "{:.2} MiB", mem).unwrap();
                } else {
                    let mem = node.mem_size as f64 / GIGABYTE as f64;
                    writeln!(&mut string, "{:.2} GiB", mem).unwrap();
                }
            });
        return Ok(string.as_bytes().to_vec());
    }

    Ok("The system has no support for NUMA\n".as_bytes().to_vec())
}
