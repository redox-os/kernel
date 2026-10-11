use super::travel_interrupt_ctrl;
use crate::{
    arch::device::irqchip::new_irqchip, cpu_set::LogicalCpuId, scheme::irq::irq_trigger,
    sync::CleanLockToken,
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    cell::SyncUnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use fdt::{node::NodeProperty, Fdt};
use spin::Once;
use syscall::{Error, Result, EINVAL};

pub unsafe trait InterruptHandler {
    unsafe fn irq_handler(&self, irq: u32, token: &mut CleanLockToken);
}

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum IrqCell {
    L1(u32),
    L2(u32, u32),
    L3(u32, u32, u32),
}

pub unsafe trait InterruptController: InterruptHandler {
    unsafe fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
        phandle: u32,
        parents: &[IrqConnection],
    ) -> Result<()>;
    unsafe fn irq_ack(&self) -> u32;
    unsafe fn irq_eoi(&self, irq_num: u32);
    unsafe fn irq_enable(&self, irq_num: u32);
    #[allow(unused)]
    unsafe fn irq_disable(&self, irq_num: u32);
    /// Configure the interrupt trigger mode from the devicetree specifier
    /// before enabling the interrupt. Controllers without configurable
    /// trigger modes may keep the default implementation.
    unsafe fn irq_configure(&self, _irq_data: IrqCell) -> Result<()> {
        Ok(())
    }
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
    pub parents: Box<[IrqConnection]>,
    pub children: Vec<usize>, // child idx in chiplist
    pub ic: Box<dyn InterruptController>,
}

pub struct IrqDescItem {
    pub idx: usize,
    pub ic_idx: usize,               //ic idx in irq chip list
    pub child_ic_idx: Option<usize>, //ic idx in irq chip list
    pub ic_irq: u32,                 //hwirq in ic
    pub used: AtomicBool,
}

pub struct IrqDesc {
    pub basic: IrqDescItem,
    pub handler: Once<Box<dyn InterruptHandler>>,
}

pub struct IrqChip {
    //TODO: support multi level interrupt constrollers
    pub chips: Once<Box<[IrqChipItem]>>,
    pub irq_desc: SyncUnsafeCell<[IrqDesc; 1024]>,
}

unsafe impl Sync for IrqChip {}

mod inner {
    use super::*;

    static IRQ_CHIP: IrqChip = IrqChip {
        chips: Once::new(),
        irq_desc: SyncUnsafeCell::new(
            [const {
                IrqDesc {
                    basic: IrqDescItem {
                        idx: 0,
                        ic_idx: 0,
                        ic_irq: 0,
                        child_ic_idx: None,
                        used: AtomicBool::new(false),
                    },
                    handler: Once::new(),
                }
            }; 1024],
        ),
    };
    impl IrqChip {
        pub fn chips() -> &'static [IrqChipItem] {
            IRQ_CHIP
                .chips
                .get()
                .expect("IrqChip::chips() called before initialization!")
        }
        pub fn descs() -> &'static [IrqDesc] {
            unsafe {
                if !IRQ_CHIP.chips.is_completed() {
                    panic!("IrqChip::descs() called before initialization!")
                }
                IRQ_CHIP.irq_desc.get().as_ref().expect("Null static???")
            }
        }
    }
    pub fn init(fdt_opt: Option<&Fdt>, chips_opt: Option<Box<[IrqChipItem]>>) {
        IRQ_CHIP.chips.call_once(|| unsafe {
            let mut chips = fdt_opt
                .map(parse_chips)
                .or(chips_opt)
                .expect("IrqChip::init called without either fdt or chips!");

            let roots = assign_children(&mut chips);

            let descs = &mut *IRQ_CHIP.irq_desc.get();

            connect_parent_irqs(&mut chips, descs, fdt_opt, roots);

            chips
        });
        println!("IrqChip initialized, chips: {}", IrqChip::chips().len());
    }
    fn parse_chips(fdt: &Fdt) -> Box<[IrqChipItem]> {
        fdt.all_nodes()
            .filter(|n| n.property("interrupt-controller").is_some())
            .filter_map(|node| {
                let (Some(compatible), Some(phandle), Some(intr_cells)) = (
                    node.compatible().map(|c| c.first()),
                    node.property("phandle")
                        .map(|p| p.as_usize().unwrap() as u32),
                    node.interrupt_cells(),
                ) else {
                    return None;
                };

                debug!(
                    "{}, compatible = {}, #interrupt-cells = 0x{:08x}, phandle = 0x{:08x}",
                    node.name, compatible, intr_cells, phandle
                );

                let Some(ic) = new_irqchip(compatible) else {
                    warn!("No drivers found, skipping");
                    return None;
                };

                let mut item_parents = Vec::new();

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

                if let (Some(parent), Some(intr_data)) =
                    (node.interrupt_parent(), node.property("interrupts"))
                {
                    // FIXME use interrupts() helper when fixed (see gh#12)
                    let mut intr_data = intr_data
                        .value
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .copied()
                        .map(u32::from_be_bytes);

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
                        item_parents.push(IrqConnection {
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
                    let mut intr_data = intr_data
                        .value
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .copied()
                        .map(u32::from_be_bytes);

                    while let Some(parent_phandle) = intr_data.next()
                        && let Some(parent_interrupt) = fdt
                            .find_phandle(parent_phandle)
                            .and_then(|p| p.interrupt_cells())
                            .and_then(|cells| interrupt_address(&mut intr_data, cells))
                    {
                        debug!("{:?}, ", parent_interrupt);
                        item_parents.push(IrqConnection {
                            parent_phandle,
                            parent: 0,
                            parent_interrupt: gate_interrupt_address(parent_interrupt),
                        });
                    }
                }
                Some(IrqChipItem {
                    phandle,
                    parents: item_parents.into_boxed_slice(),
                    children: Vec::new(),
                    ic,
                })
            })
            .collect()
    }

    fn assign_children(chips: &mut [IrqChipItem]) -> Vec<usize> {
        (0..chips.len())
            .filter(|&child_i| {
                let phandle = chips[child_i].phandle;
                let parents = &chips[child_i].parents;

                if parents.is_empty() {
                    return true;
                }

                for conn_i in 0..parents.len() {
                    let parent_phandle = chips[child_i].parents[conn_i].parent_phandle;
                    let parent_i = chips
                        .iter()
                        .position(|&IrqChipItem { phandle, .. }| parent_phandle == phandle)
                        .unwrap_or_else(|| {
                            panic!(
                                "Cannot find parent intc {} (connection from {})",
                                parent_phandle, phandle
                            )
                        });
                    chips[child_i].parents[conn_i].parent = parent_i;

                    let parent = &mut chips[parent_i];
                    if !parent.children.contains(&child_i) {
                        parent.children.push(child_i);
                    }
                }
                false
            })
            .collect()
    }

    unsafe fn connect_parent_irqs(
        chips: &mut [IrqChipItem],
        irq_desc: &mut [IrqDesc; 1024],
        fdt_opt: Option<&Fdt>,
        mut queue: Vec<usize>,
    ) -> Vec<usize> {
        unsafe {
            let mut irq_idx: usize = 0;
            let mut queue_idx = 0;

            while queue_idx < queue.len() {
                let cur_idx = queue[queue_idx];
                let cur_chip = &mut chips[cur_idx];
                let cur_chip_phandle = cur_chip.phandle;

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
                    .irq_init(
                        fdt_opt,
                        irq_desc,
                        cur_idx,
                        &mut irq_idx,
                        cur_chip.phandle,
                        &cur_chip.parents,
                    )
                    .expect("Failed to initialize irq chip");

                let mut conn_i = 0;

                while conn_i < chips[cur_idx].parents.len() {
                    let connection = &chips[cur_idx].parents[conn_i];
                    debug_assert!(queue[0..queue_idx].contains(&connection.parent));

                    if let Some(parent_interrupt) = connection.parent_interrupt {
                        let parent = &mut chips[connection.parent];

                        match parent.ic.irq_xlate(parent_interrupt) {
                            Ok(virq) => {
                                // assert is unused
                                irq_desc[virq].basic.child_ic_idx = Some(cur_idx);
                            }
                            _ => {
                                error!(
                                    "Cannot connect irq chip {} to parent irq {} : {:?}",
                                    cur_chip_phandle, parent.phandle, parent_interrupt
                                );
                            }
                        }
                    }
                    conn_i += 1;
                }

                queue_idx += 1;
            }
            queue
        }
    }
}

impl IrqChip {
    pub unsafe fn irq_eoi(virq: u32) {
        unsafe {
            let irq_desc = &Self::descs()[virq as usize];
            let ic_idx = irq_desc.basic.ic_idx;
            let hwirq = irq_desc.basic.ic_irq;

            Self::chips()[ic_idx].ic.irq_eoi(hwirq)
        }
    }

    pub unsafe fn irq_enable(virq: u32) {
        unsafe {
            let irq_desc = &Self::descs()[virq as usize];
            let ic_idx = irq_desc.basic.ic_idx;
            let hwirq = irq_desc.basic.ic_irq;

            Self::chips()[ic_idx].ic.irq_enable(hwirq)
        }
    }

    #[allow(unused)]
    unsafe fn irq_disable(virq: u32) {
        unsafe {
            let irq_desc = &Self::descs()[virq as usize];
            let ic_idx = irq_desc.basic.ic_idx;
            let hwirq = irq_desc.basic.ic_irq;

            Self::chips()[ic_idx].ic.irq_disable(hwirq)
        }
    }

    #[cfg(target_arch = "riscv64")]
    pub fn irq_to_virq(ic_idx: usize, hwirq: u32) -> Option<usize> {
        Self::chips()[ic_idx].ic.irq_to_virq(hwirq)
    }

    pub fn irq_xlate(ic_idx: usize, irq_data: &[u32]) -> Result<usize, Error> {
        let irq_data = match irq_data {
            &[a] => IrqCell::L1(a),
            &[a, b] => IrqCell::L2(a, b),
            &[a, b, c] => IrqCell::L3(a, b, c),
            _ => return Err(Error::new(EINVAL)),
        };
        Self::chips()[ic_idx].ic.irq_xlate(irq_data)
    }

    pub unsafe fn trigger_virq(virq: u32, token: &mut CleanLockToken) {
        unsafe {
            if virq < 1024 {
                let desc = &Self::descs()[virq as usize];
                match desc.handler.get() {
                    Some(handler) => {
                        handler.irq_handler(virq, token);
                    }
                    _ => {
                        if let Some(ic_idx) = desc.basic.child_ic_idx {
                            Self::chips()[ic_idx].ic.irq_handler(virq, token);
                        } else {
                            irq_trigger(virq as u8, token);
                        }
                    }
                }
            }
        }
    }

    pub fn phandle_to_ic_idx(phandle: u32) -> Option<usize> {
        Self::chips().iter().position(|x| x.phandle == phandle)
    }

    pub fn irq_iter_for(ic_idx: u32) -> impl Iterator<Item = u8> {
        Self::descs().iter().filter_map(move |x| {
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
        IrqChip::irq_eoi(irq as u32);
    }
}

pub fn init(fdt_opt: Option<&Fdt>, chips_opt: Option<Box<[IrqChipItem]>>) {
    if let Some(fdt) = fdt_opt {
        travel_interrupt_ctrl(fdt);
    }
    inner::init(fdt_opt, chips_opt);
}

pub fn register_irq(virq: u32, handler: Box<dyn InterruptHandler>) {
    if virq >= 1024 {
        error!("irq {} exceed 1024!!!", virq);
        return;
    }
    IrqChip::descs()[virq as usize]
        .handler
        .call_once(|| handler);
}

#[inline]
pub fn is_reserved(_cpu_id: LogicalCpuId, index: u8) -> bool {
    IrqChip::descs()[index as usize]
        .basic
        .used
        .load(Ordering::Relaxed)
}
// TODO make reservation atomic!
#[inline]
pub fn set_reserved(_cpu_id: LogicalCpuId, index: u8, reserved: bool) {
    unsafe {
        IrqChip::descs()[index as usize]
            .basic
            .used
            .store(reserved, Ordering::Relaxed);
        if reserved {
            IrqChip::irq_enable(index as u32);
        } else {
            IrqChip::irq_disable(index as u32);
        }
    }
}

pub fn available_irqs_iter(_cpu_id: LogicalCpuId) -> impl Iterator<Item = u8> + 'static {
    error!("available_irqs_iter has been called");
    0..0
}
