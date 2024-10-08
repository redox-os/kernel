use alloc::{boxed::Box, vec::Vec};
use byteorder::{ByteOrder, BE};
use fdt::Fdt;
use syscall::Result;

use crate::init::device_tree::travel_interrupt_ctrl;
use log::{debug, error};

mod gic;
mod gicv3;
mod irq_bcm2835;
mod irq_bcm2836;

pub trait InterruptController {
    fn irq_init(
        &mut self,
        fdt: &Fdt,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> Result<Option<usize>>;
    fn irq_ack(&mut self) -> u32;
    fn irq_eoi(&mut self, irq_num: u32);
    fn irq_enable(&mut self, irq_num: u32);
    #[allow(unused)]
    fn irq_disable(&mut self, irq_num: u32);
    fn irq_xlate(&mut self, irq_data: &[u32], idx: usize) -> Result<usize>;
    fn irq_to_virq(&mut self, hwirq: u32) -> Option<usize>;
    fn irq_handler(&mut self, irq: u32);
}

pub trait InterruptHandler {
    fn irq_handler(&mut self, irq: u32);
}

pub struct IrqChipItem {
    pub phandle: u32,
    pub parent_phandle: Option<u32>,
    pub parent: Option<usize>, //parent idx in chiplist
    pub childs: Vec<usize>,    //child idx in chiplist
    pub interrupts: Vec<u32>,
    pub ic: Box<dyn InterruptController>,
}

pub struct IrqChipList {
    pub chips: Vec<IrqChipItem>,
    pub root_phandle: u32,
    pub root_idx: usize,
}

pub struct IrqDescItem {
    pub idx: usize,
    pub ic_idx: usize,               //ic idx in irq chip list
    pub child_ic_idx: Option<usize>, //ic idx in irq chip list
    pub ic_irq: u32,                 //hwirq in ic
    pub used: bool,
}

pub struct IrqDesc {
    pub basic: IrqDescItem,
    pub handler: Option<Box<dyn InterruptHandler>>,
}

impl IrqChipList {
    fn init_inner1(&mut self, fdt: &Fdt) {
        let root_node = fdt.root();
        let mut idx = 0;
        let intr = root_node.property("interrupt-parent").unwrap();

        let root_intr_parent = intr.as_usize().unwrap() as u32;
        debug!("root parent = 0x{:08x}", root_intr_parent);
        self.root_phandle = root_intr_parent;
        for node in fdt.all_nodes() {
            if node.property("interrupt-controller").is_some() {
                let compatible = node.property("compatible").unwrap().as_str().unwrap();
                let phandle = node.property("phandle").unwrap().as_usize().unwrap() as u32;
                let intr_cells = node.interrupt_cells().unwrap();
                let _intr = node.property("interrupt-parent");
                let _intr_data = node.property("interrupts");

                debug!(
                    "{}, compatible = {}, #interrupt-cells = 0x{:08x}, phandle = 0x{:08x}",
                    node.name, compatible, intr_cells, phandle
                );
                let mut item = IrqChipItem {
                    phandle,
                    parent_phandle: None,
                    parent: None,
                    childs: Vec::new(),
                    interrupts: Vec::new(),
                    ic: IrqChipCore::new_ic(compatible).unwrap(),
                };
                if let Some(intr) = _intr {
                    if let Some(intr_data) = _intr_data {
                        let intr = intr.as_usize().unwrap() as u32;
                        debug!("interrupt-parent = 0x{:08x}", intr);
                        item.parent_phandle = Some(intr);
                        debug!("interrupts begin:");
                        for chunk in intr_data.value.chunks(4) {
                            debug!("0x{:08x}, ", BE::read_u32(chunk));
                            item.interrupts.push(BE::read_u32(chunk));
                        }
                        debug!("interrupts end");
                    }
                }
                if item.phandle == root_intr_parent {
                    self.root_idx = idx as usize;
                }

                self.chips.push(item);

                idx += 1;
            }
        }
    }

    fn init_inner2(&mut self) {
        let mut x = 0;

        while x < self.chips.len() {
            let mut y = 0;
            while y < self.chips.len() {
                if x == y {
                    y += 1;
                    continue;
                }
                if let Some(pp) = self.chips[y].parent_phandle
                    && pp == self.chips[x].phandle
                {
                    self.chips[y].parent = Some(x);
                    self.chips[x].childs.push(y);
                }
                y += 1;
            }
            x += 1;
        }
    }

    fn init_inner3(&mut self, fdt: &fdt::Fdt, irq_desc: &mut [IrqDesc; 1024]) {
        //run init
        let mut queue = Vec::new();
        let mut irq_idx: usize = 0;
        queue.push(self.root_idx);
        while !queue.is_empty() {
            let cur_idx = queue.pop().unwrap();
            queue.extend_from_slice(&self.chips[cur_idx].childs);
            let virq = self.chips[cur_idx]
                .ic
                .irq_init(fdt, irq_desc, cur_idx, &mut irq_idx);
            if let Ok(Some(virq)) = virq {
                irq_desc[virq].basic.child_ic_idx = Some(cur_idx);
            }
        }
    }
}

pub struct IrqChipCore {
    //TODO: support multi level interrupt constrollers
    pub irq_chip_list: IrqChipList,
    pub irq_desc: [IrqDesc; 1024],
}

impl IrqChipCore {
    pub fn irq_ack(&mut self) -> u32 {
        self.irq_chip_list.chips[self.irq_chip_list.root_idx]
            .ic
            .irq_ack()
    }

    pub fn irq_eoi(&mut self, virq: u32) {
        let irq_desc = &self.irq_desc[virq as usize];
        let ic_idx = irq_desc.basic.ic_idx;
        let hwirq = irq_desc.basic.ic_irq;

        self.irq_chip_list.chips[ic_idx].ic.irq_eoi(hwirq)
    }

    pub fn irq_enable(&mut self, virq: u32) {
        let irq_desc = &self.irq_desc[virq as usize];
        let ic_idx = irq_desc.basic.ic_idx;
        let hwirq = irq_desc.basic.ic_irq;

        self.irq_chip_list.chips[ic_idx].ic.irq_enable(hwirq)
    }

    #[allow(unused)]
    pub fn irq_disable(&mut self, virq: u32) {
        let irq_desc = &self.irq_desc[virq as usize];
        let ic_idx = irq_desc.basic.ic_idx;
        let hwirq = irq_desc.basic.ic_irq;

        self.irq_chip_list.chips[ic_idx].ic.irq_disable(hwirq)
    }

    pub fn irq_to_virq(&mut self, hwirq: u32) -> Option<usize> {
        self.irq_chip_list.chips[self.irq_chip_list.root_idx]
            .ic
            .irq_to_virq(hwirq)
    }

    pub fn init(&mut self, fdt: &Fdt) {
        for i in 0..1024 {
            self.irq_desc[i].basic.idx = i;
        }
        self.irq_chip_list.init_inner1(fdt);
        self.irq_chip_list.init_inner2();
        self.irq_chip_list.init_inner3(fdt, &mut self.irq_desc);
    }

    pub fn new_ic(ic_str: &str) -> Option<Box<dyn InterruptController>> {
        if ic_str.contains("arm,gic-v3") {
            Some(Box::new(gicv3::GicV3::new()))
        } else if ic_str.contains("arm,cortex-a15-gic") {
            Some(Box::new(gic::GenericInterruptController::new()))
        } else if ic_str.contains("brcm,bcm2836-l1-intc") {
            Some(Box::new(irq_bcm2836::Bcm2836ArmInterruptController::new()))
        } else if ic_str.contains("brcm,bcm2836-armctrl-ic") {
            Some(Box::new(irq_bcm2835::Bcm2835ArmInterruptController::new()))
        } else {
            log::warn!("no driver for interrupt controller {:?}", ic_str);
            None
        }
    }
}

const INIT_HANDLER: Option<Box<dyn InterruptHandler>> = None;
const INIT_IRQ_DESC: IrqDesc = IrqDesc {
    basic: IrqDescItem {
        idx: 0,
        ic_idx: 0,
        ic_irq: 0,
        child_ic_idx: None,
        used: false,
    },
    handler: INIT_HANDLER,
};
pub static mut IRQ_CHIP: IrqChipCore = IrqChipCore {
    irq_chip_list: IrqChipList {
        chips: Vec::new(),
        root_phandle: 0,
        root_idx: 0,
    },
    irq_desc: [INIT_IRQ_DESC; 1024],
};

pub fn init(fdt: &Fdt) {
    travel_interrupt_ctrl(fdt);
    unsafe {
        IRQ_CHIP.init(fdt);
    }
}

pub fn register_irq(virq: u32, handler: Box<dyn InterruptHandler>) {
    if virq >= 1024 {
        error!("irq {} exceed 1024!!!", virq);
        return;
    }

    unsafe {
        if IRQ_CHIP.irq_desc[virq as usize].handler.is_some() {
            error!("irq {} has already been registered!", virq);
            return;
        }

        IRQ_CHIP.irq_desc[virq as usize].handler = Some(handler);
    }
}
