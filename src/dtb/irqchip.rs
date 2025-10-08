use super::travel_interrupt_ctrl;
use crate::{
    arch::device::irqchip::new_irqchip, cpu_set::LogicalCpuId, scheme::irq::irq_trigger,
    sync::CleanLockToken,
};
use alloc::{boxed::Box, vec::Vec};
use byteorder::{ByteOrder, BE};
use fdt::{node::NodeProperty, Fdt};
use syscall::{Error, Result, EINVAL};

pub trait InterruptHandler {
    fn irq_handler(&mut self, irq: u32, token: &mut CleanLockToken);
}

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum IrqCell {
    L1(u32),
    L2(u32, u32),
    L3(u32, u32, u32),
}

pub trait InterruptController: InterruptHandler {
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> Result<()>;
    fn irq_ack(&mut self) -> u32;
    fn irq_eoi(&mut self, irq_num: u32);
    fn irq_enable(&mut self, irq_num: u32);
    #[allow(unused)]
    fn irq_disable(&mut self, irq_num: u32);
    fn irq_xlate(&self, irq_data: IrqCell) -> Result<usize>;
    fn irq_to_virq(&self, hwirq: u32) -> Option<usize>;
}

pub struct IrqConnection {
    pub parent_phandle: u32,
    pub parent: usize, // parent idx in chiplist
    pub parent_interrupt: Option<IrqCell>,
}

pub struct IrqChipItem {
    pub phandle: u32,
    pub parents: Vec<IrqConnection>,
    pub children: Vec<usize>, // child idx in chiplist
    pub ic: Box<dyn InterruptController>,
}

pub struct IrqChipList {
    pub chips: Vec<IrqChipItem>,
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
        for node in fdt.all_nodes() {
            if node.property("interrupt-controller").is_some() {
                let Some(compatible) = node.compatible() else {
                    continue;
                };
                let compatible = compatible.first();
                let Some(phandle) = node.property("phandle") else {
                    continue;
                };
                let phandle = phandle.as_usize().unwrap() as u32;
                let Some(intr_cells) = node.interrupt_cells() else {
                    continue;
                };

                debug!(
                    "{}, compatible = {}, #interrupt-cells = 0x{:08x}, phandle = 0x{:08x}",
                    node.name, compatible, intr_cells, phandle
                );
                let mut item = IrqChipItem {
                    phandle,
                    parents: Vec::new(),
                    children: Vec::new(),
                    ic: new_irqchip(compatible).unwrap(),
                };

                fn interrupt_address(
                    iter: &mut impl Iterator<Item = u32>,
                    interrupt_cells: usize,
                ) -> Option<IrqCell> {
                    match interrupt_cells {
                        1 => Some(IrqCell::L1(iter.next()?)),
                        2 if let Ok([a, b]) = iter.next_chunk() => Some(IrqCell::L2(a, b)),
                        3 if let Ok([a, b, c]) = iter.next_chunk() => Some(IrqCell::L3(a, b, c)),
                        _ => None,
                    }
                }

                fn gate_interrupt_address(addr: IrqCell) -> Option<IrqCell> {
                    match addr {
                        IrqCell::L1(u32::MAX)
                        | IrqCell::L2(u32::MAX, _)
                        | IrqCell::L3(u32::MAX, _, _) => None,
                        _ => Some(addr),
                    }
                }

                if let Some(parent) = node.interrupt_parent()
                    && let Some(intr_data) = node.property("interrupts")
                {
                    // FIXME use interrupts() helper when fixed (see gh#12)
                    let mut intr_data = intr_data.value.chunks(4).map(|x| BE::read_u32(x));
                    let parent_phandle = parent
                        .property("phandle")
                        .and_then(NodeProperty::as_usize)
                        .unwrap() as u32;
                    let parent_interrupt_cells = parent.interrupt_cells().unwrap();
                    debug!("interrupt-parent = 0x{:08x}", parent_phandle);
                    debug!("interrupts begin:");
                    while let Some(parent_interrupt) =
                        interrupt_address(&mut intr_data, parent_interrupt_cells)
                    {
                        debug!("{:?}, ", parent_interrupt);
                        item.parents.push(IrqConnection {
                            parent_phandle,
                            parent: 0,
                            parent_interrupt: gate_interrupt_address(parent_interrupt),
                        });
                    }
                    debug!("interrupts end");
                } else if let Some(intr_data) = node.property("interrupts-extended") {
                    // FIXME use the helper when fixed (see gh#37)
                    // Shouldn't matter much since ARM seems to not use extended interrupt and
                    // RISC-V seems to not use 3-sized interrupt addresses
                    let mut intr_data = intr_data.value.chunks(4).map(|x| BE::read_u32(x));
                    while let Some(parent_phandle) = intr_data.next()
                        && let Some(parent) = fdt.find_phandle(parent_phandle)
                        && let Some(parent_interrupt_cells) = parent.interrupt_cells()
                        && let Some(parent_interrupt) =
                            interrupt_address(&mut intr_data, parent_interrupt_cells)
                    {
                        debug!("{:?}, ", parent_interrupt);
                        item.parents.push(IrqConnection {
                            parent_phandle,
                            parent: 0,
                            parent_interrupt: gate_interrupt_address(parent_interrupt),
                        });
                    }
                }

                self.chips.push(item);
            }
        }
    }

    fn init_inner2(&mut self) -> Vec<usize> {
        let mut roots = Vec::new();

        for child_i in 0..self.chips.len() {
            let child = &mut self.chips[child_i];
            let phandle = child.phandle;

            if child.parents.is_empty() {
                roots.push(child_i);
                continue;
            }

            for conn_i in 0..child.parents.len() {
                let parent_phandle = self.chips[child_i].parents[conn_i].parent_phandle;
                let parent_i = self
                    .chips
                    .iter()
                    .position(|x| parent_phandle == x.phandle)
                    .unwrap_or_else(|| {
                        panic!(
                            "Cannot find parent intc {} (connection from {})",
                            parent_phandle, phandle
                        )
                    });
                self.chips[child_i].parents[conn_i].parent = parent_i;
                let parent = &mut self.chips[parent_i];
                if !parent.children.contains(&child_i) {
                    parent.children.push(child_i);
                }
            }
        }
        roots
    }

    fn init_inner3(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        mut queue: Vec<usize>,
    ) {
        //run init
        let mut irq_idx: usize = 0;
        let mut queue_idx = 0;
        while queue_idx < queue.len() {
            let cur_idx = queue[queue_idx];
            let cur_chip = &mut self.chips[cur_idx];
            for child in &cur_chip.children {
                if let Some(child_pos) = queue.iter().position(|x| *child == *x) {
                    assert!(
                        child_pos > queue_idx,
                        "IRQ chip tree has a cycle with phandle {} in it",
                        cur_chip.phandle
                    );
                } else {
                    queue.push(*child);
                }
            }
            cur_chip
                .ic
                .irq_init(fdt_opt, irq_desc, cur_idx, &mut irq_idx)
                .expect("Failed to initialize irq chip");

            let cur_chip = &self.chips[cur_idx];
            for connection in &cur_chip.parents {
                debug_assert!(queue[0..queue_idx].contains(&connection.parent));
                if let Some(parent_interrupt) = connection.parent_interrupt {
                    let parent = &self.chips[connection.parent];
                    match parent.ic.irq_xlate(parent_interrupt) {
                        Ok(virq) => {
                            // assert is unused
                            irq_desc[virq].basic.child_ic_idx = Some(cur_idx);
                        }
                        _ => {
                            error!(
                                "Cannot connect irq chip {} to parent irq {} : {:?}",
                                cur_chip.phandle, parent.phandle, parent_interrupt
                            );
                        }
                    }
                }
            }

            queue_idx += 1;
        }
    }
}

pub struct IrqChipCore {
    //TODO: support multi level interrupt constrollers
    pub irq_chip_list: IrqChipList,
    pub irq_desc: [IrqDesc; 1024],
}

impl IrqChipCore {
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

    #[cfg(target_arch = "riscv64")]
    pub fn irq_to_virq(&self, ic_idx: usize, hwirq: u32) -> Option<usize> {
        self.irq_chip_list.chips[ic_idx].ic.irq_to_virq(hwirq)
    }

    pub fn irq_xlate(&self, ic_idx: usize, irq_data: &[u32]) -> Result<usize, Error> {
        let irq_data = match irq_data.len() {
            1 => IrqCell::L1(irq_data[0]),
            2 => IrqCell::L2(irq_data[0], irq_data[1]),
            3 => IrqCell::L3(irq_data[0], irq_data[1], irq_data[2]),
            _ => return Err(Error::new(EINVAL)),
        };
        self.irq_chip_list.chips[ic_idx].ic.irq_xlate(irq_data)
    }

    pub fn trigger_virq(&mut self, virq: u32, token: &mut CleanLockToken) {
        if virq < 1024 {
            let desc = &mut self.irq_desc[virq as usize];
            match &mut desc.handler {
                Some(handler) => {
                    handler.irq_handler(virq, token);
                }
                _ => {
                    if let Some(ic_idx) = desc.basic.child_ic_idx {
                        self.irq_chip_list.chips[ic_idx].ic.irq_handler(virq, token);
                    } else {
                        irq_trigger(virq as u8, token);
                    }
                }
            }
        }
    }

    pub fn init(&mut self, fdt_opt: Option<&Fdt>) {
        for (i, desc) in self.irq_desc.iter_mut().enumerate() {
            desc.basic.idx = i;
        }
        if let Some(fdt) = fdt_opt {
            self.irq_chip_list.init_inner1(fdt);
        }
        let roots = self.irq_chip_list.init_inner2();
        self.irq_chip_list
            .init_inner3(fdt_opt, &mut self.irq_desc, roots);
    }

    pub fn phandle_to_ic_idx(&self, phandle: u32) -> Option<usize> {
        self.irq_chip_list
            .chips
            .iter()
            .position(|x| x.phandle == phandle)
    }

    pub fn irq_iter_for(&self, ic_idx: u32) -> impl Iterator<Item = u8> + '_ {
        self.irq_desc.iter().filter_map(move |x| {
            if x.basic.ic_idx == ic_idx as usize {
                Some(x.basic.ic_irq as u8)
            } else {
                None
            }
        })
    }
}

pub unsafe fn acknowledge(irq: usize) {
    unsafe {
        IRQ_CHIP.irq_eoi(irq as u32);
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
    irq_chip_list: IrqChipList { chips: Vec::new() },
    irq_desc: [INIT_IRQ_DESC; 1024],
};

pub fn init(fdt: &Fdt) {
    travel_interrupt_ctrl(fdt);
    unsafe {
        IRQ_CHIP.init(Some(fdt));
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

#[inline]
pub fn is_reserved(_cpu_id: LogicalCpuId, index: u8) -> bool {
    unsafe { IRQ_CHIP.irq_desc[index as usize].basic.used }
}

#[inline]
pub fn set_reserved(_cpu_id: LogicalCpuId, index: u8, reserved: bool) {
    unsafe {
        IRQ_CHIP.irq_desc[index as usize].basic.used = reserved;
        if reserved {
            IRQ_CHIP.irq_enable(index as u32);
        } else {
            IRQ_CHIP.irq_enable(index as u32);
        }
    }
}

pub fn available_irqs_iter(_cpu_id: LogicalCpuId) -> impl Iterator<Item = u8> + 'static {
    error!("available_irqs_iter has been called");
    0..0
}
