use byteorder::{ByteOrder, BE};
use fdt::{node::NodeProperty, Fdt};
use log::debug;

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
