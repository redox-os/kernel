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

/// Interrupt handlers are shared between every CPU that can take the
/// interrupt, so they are only ever reachable through a shared reference and
/// have to provide their own interior synchronization.
pub trait InterruptHandler: Send + Sync {
    fn irq_handler(&self, irq: u32, token: &mut CleanLockToken);
}

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum IrqCell {
    L1(u32),
    L2(u32, u32),
    L3(u32, u32, u32),
}

pub trait InterruptController: InterruptHandler {
    /// Bring the controller up once on the boot CPU, before it is published.
    ///
    /// This function is called during the initialization of IrqChip, which is not accessible yet!
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
        phandle: u32,
        parents: &[IrqConnection],
    ) -> Result<()>;
    fn irq_ack(&self) -> u32;
    fn irq_eoi(&self, irq_num: u32);
    fn irq_enable(&self, irq_num: u32);
    #[allow(unused)]
    fn irq_disable(&self, irq_num: u32);
    /// Configure the interrupt trigger mode from the devicetree specifier
    /// before enabling the interrupt. Controllers without configurable
    /// trigger modes may keep the default implementation.
    fn irq_configure(&self, _irq_data: IrqCell) -> Result<()> {
        Ok(())
    }
    fn irq_xlate(&self, irq_data: IrqCell) -> Result<usize>;
    fn irq_to_virq(&self, hwirq: u32) -> Option<usize>;
}

pub struct IrqConnection {
    pub parent_phandle: u32,
    /// parent index in IrqChip::chips()
    pub parent: usize,
    pub parent_interrupt: Option<IrqCell>,
}

pub struct IrqChipItem {
    pub phandle: u32,
    pub parents: Vec<IrqConnection>,
    /// child indices in IrqChip::chips()
    pub children: Vec<usize>,
    pub ic: Box<dyn InterruptController>,
}

pub struct IrqDescItem {
    pub ic_idx: usize,               // ic idx in irq chip list
    pub child_ic_idx: Option<usize>, // ic idx in irq chip list, or NO_CHILD_IC
    pub ic_irq: u32,                 // hwirq in ic
    used: AtomicBool,
}

impl IrqDescItem {
    #[inline]
    pub fn set_used(&self, used: bool) {
        self.used.store(used, Ordering::Release);
    }

    /// Claim this IRQ for a single owner. Returns `false` if it was already
    /// taken, including when another CPU is racing us for the same one.
    #[inline]
    pub fn try_set_used(&self) -> bool {
        self.used
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Point this descriptor at `ic_irq` of chip `ic_idx`. Only called while
    /// the boot CPU initializes the controllers.
    #[inline]
    pub fn set_mapping(&mut self, ic_idx: usize, ic_irq: u32) {
        self.ic_irq = ic_irq;
        self.ic_idx = ic_idx;
    }
}

pub struct IrqDesc {
    pub basic: IrqDescItem,
    pub handler: Once<Box<dyn InterruptHandler>>,
}
impl IrqDesc {
    const fn new() -> Self {
        Self {
            basic: IrqDescItem {
                ic_idx: 0,
                ic_irq: 0,
                child_ic_idx: None,
                used: AtomicBool::new(false),
            },
            handler: Once::new(),
        }
    }
}

pub use inner::IrqChip;
mod inner {
    use super::*;

    pub struct IrqChip {
        //TODO: support multi level interrupt constrollers
        /// Populated exactly once, by [`init_with_fdt`] / [`init_with_chips`] on the boot CPU, and read-only
        /// afterwards.
        // SAFETY: used to synchronize and gate irq_desc!
        chips: Once<Box<[IrqChipItem]>>,
        // irq_desc uses chips to enforce initialization and should only be modified from the same call_once
        irq_desc: SyncUnsafeCell<[IrqDesc; 1024]>,
    }

    static IRQ_CHIP: IrqChip = IrqChip {
        chips: Once::new(),
        irq_desc: SyncUnsafeCell::new([const { IrqDesc::new() }; 1024]),
    };

    impl IrqChip {
        #[inline]
        pub fn chips() -> &'static [IrqChipItem] {
            IRQ_CHIP
                .chips
                .get()
                .expect("IrqChip::chips() called before initialization!")
        }
        #[inline]
        pub fn descs() -> &'static [IrqDesc; 1024] {
            unsafe {
                if !IRQ_CHIP.chips.is_completed() {
                    panic!("IrqChip::descs() called before initialization!");
                }
                &*IRQ_CHIP.irq_desc.get()
            }
        }
        pub fn init_with_fdt(fdt: &Fdt) {
            travel_interrupt_ctrl(fdt);
            Self::init(Self::parse_fdt_chips(fdt), Some(fdt));
        }
        /// Publish a controller list assembled by the platform (ACPI) instead of the
        /// devicetree.
        #[allow(dead_code)]
        pub fn init_with_chips(chips: Box<[IrqChipItem]>) {
            Self::init(chips, None);
        }
        fn init(mut chips: Box<[IrqChipItem]>, fdt_opt: Option<&Fdt>) {
            unsafe {
                IRQ_CHIP.chips.call_once(move || {
                    let roots = Self::assign_children(&mut chips);
                    Self::connect_parent_irqs(
                        &mut chips,
                        IRQ_CHIP
                            .irq_desc
                            .get()
                            .as_mut()
                            .expect("IRQ_CHIP.irq_desc should never be null!"),
                        fdt_opt,
                        roots,
                    );
                    chips
                });
            }
        }
    }
}

impl IrqChip {
    fn parse_fdt_chips(fdt: &Fdt) -> Box<[IrqChipItem]> {
        fdt.all_nodes()
            .filter(|n| n.property("interrupt-controller").is_some())
            .filter_map(|node| {
                let (Some(compatible), Some(phandle), Some(intr_cells)) = (
                    node.compatible().map(|c| c.first()),
                    node.property("phandle")
                        .and_then(|p| p.as_usize())
                        .and_then(|p| p.try_into().ok()),
                    node.interrupt_cells(),
                ) else {
                    warn!(
                        "Failed to parse properties of interrupt controller: {}",
                        node.name
                    );
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
                        .expect("Failed to parse IC parent phandle property as usize!")
                        as u32;

                    let parent_interrupt_cells = parent
                        .interrupt_cells()
                        .expect("Failed to parse IC parent interrupt cells!");

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
                    parents: item_parents,
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
    fn connect_parent_irqs(
        chips: &mut [IrqChipItem],
        irq_desc: &mut [IrqDesc; 1024],
        fdt_opt: Option<&Fdt>,
        mut queue: Vec<usize>,
    ) {
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
    }

    #[inline]
    pub fn chip(ic_idx: usize) -> &'static IrqChipItem {
        &Self::chips()[ic_idx]
    }

    pub fn irq_eoi(virq: u32) {
        let irq_desc = &Self::descs()[virq as usize];

        Self::chip(irq_desc.basic.ic_idx)
            .ic
            .irq_eoi(irq_desc.basic.ic_irq)
    }

    pub fn irq_enable(virq: u32) {
        let irq_desc = &Self::descs()[virq as usize];

        Self::chip(irq_desc.basic.ic_idx)
            .ic
            .irq_enable(irq_desc.basic.ic_irq)
    }

    #[allow(unused)]
    pub fn irq_disable(virq: u32) {
        let irq_desc = &Self::descs()[virq as usize];

        Self::chip(irq_desc.basic.ic_idx)
            .ic
            .irq_disable(irq_desc.basic.ic_irq)
    }

    #[cfg(target_arch = "riscv64")]
    pub fn irq_to_virq(ic_idx: usize, hwirq: u32) -> Option<usize> {
        Self::chip(ic_idx).ic.irq_to_virq(hwirq)
    }

    pub fn irq_xlate(ic_idx: usize, irq_data: &[u32]) -> Result<usize, Error> {
        let irq_data = match *irq_data {
            [a] => IrqCell::L1(a),
            [a, b] => IrqCell::L2(a, b),
            [a, b, c] => IrqCell::L3(a, b, c),
            _ => return Err(Error::new(EINVAL)),
        };
        Self::chip(ic_idx).ic.irq_xlate(irq_data)
    }

    pub fn trigger_virq(virq: u32, token: &mut CleanLockToken) {
        if virq < 1024 {
            let desc = &Self::descs()[virq as usize];
            match &desc.handler.get() {
                Some(handler) => {
                    handler.irq_handler(virq, token);
                }
                _ => {
                    if let Some(ic_idx) = desc.basic.child_ic_idx {
                        Self::chip(ic_idx).ic.irq_handler(virq, token);
                    } else {
                        irq_trigger(virq as u8, token);
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

/// # Safety
///
/// Kept `unsafe` to match the signature of the x86 counterpart used by the
/// `irq:` scheme. The body itself is safe.
pub unsafe fn acknowledge(irq: usize) {
    IrqChip::irq_eoi(irq as u32);
}

pub fn register_irq(virq: u32, handler: Box<dyn InterruptHandler>) {
    if virq >= 1024 {
        error!("irq {} exceed 1024!!!", virq);
        return;
    }

    let desc = &IrqChip::descs()[virq as usize];
    let mut handler = Some(handler);
    desc.handler.call_once(|| {
        handler
            .take()
            .expect("Once::call_once ran the initializer twice")
    });

    if handler.is_some() {
        error!("irq {} has already been registered!", virq);
    }
}

/// Order MMIO this CPU has already issued before a following release store to
/// normal memory.
///
/// Descriptor atomics order normal memory only. Volatile MMIO accesses do not
/// add ordering. These helpers bridge the two ordering domains.
///
/// Only aarch64 and riscv64 build `dtb`. A third architecture has to add the
/// barrier its own device mapping requires instead of inheriting one of these.
#[inline]
pub fn mmio_before_release() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags))
    };
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence o, w", options(nostack, preserves_flags))
    };
}

/// Order an acquire load of normal memory before MMIO this CPU issues after
/// it. The counterpart of [`mmio_before_release`].
#[inline]
pub fn mmio_after_acquire() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags))
    };
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence r, o", options(nostack, preserves_flags))
    };
}

/// Reserve `index` for a single owner, unmasking it on the chip if we won the
/// race. Returns `false` if it was already reserved.
///
/// The successful `compare_exchange` grants the sole right to touch the chip.
#[inline]
#[must_use]
pub fn try_set_reserved(_cpu_id: LogicalCpuId, index: u8) -> bool {
    if !IrqChip::descs()[index as usize].basic.try_set_used() {
        return false;
    }
    mmio_after_acquire();
    IrqChip::irq_enable(index as u32);
    true
}

/// Release a reservation taken by [`try_set_reserved`].
///
/// The chip must be masked before the descriptor is handed back. Otherwise a
/// new owner could unmask it before this CPU masks it again. The release store
/// is the handoff point, so a later successful acquisition follows the mask.
#[inline]
pub fn free_reserved(_cpu_id: LogicalCpuId, index: u8) {
    IrqChip::irq_disable(index as u32);
    mmio_before_release();
    IrqChip::descs()[index as usize].basic.set_used(false);
}

pub fn available_irqs_iter(_cpu_id: LogicalCpuId) -> impl Iterator<Item = u8> + 'static {
    error!("available_irqs_iter has been called");
    0..0
}
