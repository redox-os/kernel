use super::travel_interrupt_ctrl;
use crate::{
    arch::device::irqchip::new_irqchip, cpu_set::LogicalCpuId, scheme::irq::irq_trigger,
    sync::CleanLockToken,
};
use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
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
    /// `chips` lets a controller inspect an already-initialized parent. Its
    /// own entry contains a placeholder during this call, so its `ic` must not
    /// be used.
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &[IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
        chips: &[IrqChipItem],
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

/// Placeholder swapped into the chip list while a controller is running its
/// own [`InterruptController::irq_init`], so that the initializer can still
/// read the rest of the list.
struct UninitController;

impl InterruptHandler for UninitController {
    fn irq_handler(&self, _irq: u32, _token: &mut CleanLockToken) {
        unreachable!("interrupt on a controller that is still initializing")
    }
}

impl InterruptController for UninitController {
    fn irq_init(
        &mut self,
        _fdt_opt: Option<&Fdt>,
        _irq_desc: &[IrqDesc; 1024],
        _ic_idx: usize,
        _irq_idx: &mut usize,
        _chips: &[IrqChipItem],
    ) -> Result<()> {
        unreachable!()
    }
    fn irq_ack(&self) -> u32 {
        unreachable!()
    }
    fn irq_eoi(&self, _irq_num: u32) {
        unreachable!()
    }
    fn irq_enable(&self, _irq_num: u32) {
        unreachable!()
    }
    fn irq_disable(&self, _irq_num: u32) {
        unreachable!()
    }
    fn irq_xlate(&self, _irq_data: IrqCell) -> Result<usize> {
        unreachable!()
    }
    fn irq_to_virq(&self, _hwirq: u32) -> Option<usize> {
        unreachable!()
    }
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

/// Sentinel for [`IrqDescItem::child_ic_idx`], which is logically an
/// `Option<usize>` but has to be readable from other CPUs without a lock.
const NO_CHILD_IC: usize = usize::MAX;

/// The routing of a single virtual IRQ.
///
/// Every field is written while the boot CPU builds the tables, except
/// `used`, which the `irq:` scheme flips at runtime from whichever CPU the
/// calling driver happens to run on. They are therefore all atomics. The
/// descriptors live in a `static` shared by every CPU.
///
/// The descriptors are not published by the `Once` that publishes
/// [`IrqChipCore::chips`], so they carry their own ordering. The boot CPU
/// stores the routing with `Release` and every reader loads it with
/// `Acquire`. That pairing is what makes the tables the boot CPU built
/// visible to a CPU that reaches a descriptor before it looks at `chips`.
pub struct IrqDescItem {
    ic_idx: AtomicUsize,       // ic idx in irq chip list
    child_ic_idx: AtomicUsize, // ic idx in irq chip list, or NO_CHILD_IC
    ic_irq: AtomicU32,         // hwirq in ic
    used: AtomicBool,
}

impl IrqDescItem {
    #[inline]
    pub fn ic_idx(&self) -> usize {
        self.ic_idx.load(Ordering::Acquire)
    }

    #[inline]
    pub fn ic_irq(&self) -> u32 {
        self.ic_irq.load(Ordering::Acquire)
    }

    #[inline]
    pub fn child_ic_idx(&self) -> Option<usize> {
        match self.child_ic_idx.load(Ordering::Acquire) {
            NO_CHILD_IC => None,
            idx => Some(idx),
        }
    }

    #[inline]
    pub fn used(&self) -> bool {
        self.used.load(Ordering::Acquire)
    }

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
    pub fn set_mapping(&self, ic_idx: usize, ic_irq: u32) {
        self.ic_irq.store(ic_irq, Ordering::Release);
        self.ic_idx.store(ic_idx, Ordering::Release);
    }

    #[inline]
    fn set_child_ic_idx(&self, child_ic_idx: usize) {
        self.child_ic_idx.store(child_ic_idx, Ordering::Release);
    }
}

pub struct IrqDesc {
    pub basic: IrqDescItem,
    /// Write-once: Registered while the device drivers are brought up, read
    /// from interrupt context on any CPU afterwards.
    handler: Once<Box<dyn InterruptHandler>>,
}

impl IrqDesc {
    #[inline]
    pub fn handler(&self) -> Option<&dyn InterruptHandler> {
        self.handler.get().map(|handler| &**handler)
    }
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
                    let mut intr_data = intr_data
                        .value
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|&x| u32::from_be_bytes(x));
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
                    let mut intr_data = intr_data
                        .value
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|&x| u32::from_be_bytes(x));
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
        irq_desc: &[IrqDesc; 1024],
        mut queue: Vec<usize>,
    ) {
        //run init
        let mut irq_idx: usize = 0;
        let mut queue_idx = 0;
        while queue_idx < queue.len() {
            let cur_idx = queue[queue_idx];
            let cur_chip = &self.chips[cur_idx];
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

            let mut ic = core::mem::replace(
                &mut self.chips[cur_idx].ic,
                Box::new(UninitController) as Box<dyn InterruptController>,
            );
            let result = ic.irq_init(fdt_opt, irq_desc, cur_idx, &mut irq_idx, &self.chips);
            self.chips[cur_idx].ic = ic;
            result.expect("Failed to initialize irq chip");

            let cur_chip = &self.chips[cur_idx];
            for connection in &cur_chip.parents {
                debug_assert!(queue[0..queue_idx].contains(&connection.parent));
                if let Some(parent_interrupt) = connection.parent_interrupt {
                    let parent = &self.chips[connection.parent];
                    match parent.ic.irq_xlate(parent_interrupt) {
                        Ok(virq) => {
                            // assert is unused
                            irq_desc[virq].basic.set_child_ic_idx(cur_idx);
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
    /// Populated exactly once, by [`init`] on the boot CPU, and read-only
    /// afterwards. `Once` is what makes the publication visible to the other
    /// CPUs without a lock on the interrupt path.
    chips: Once<Box<[IrqChipItem]>>,
    pub irq_desc: [IrqDesc; 1024],
}

impl IrqChipCore {
    #[inline]
    pub fn chips(&self) -> &[IrqChipItem] {
        self.chips.get().map_or(&[], |chips| chips)
    }

    #[inline]
    pub fn chip(&self, ic_idx: usize) -> &IrqChipItem {
        &self.chips()[ic_idx]
    }

    pub fn irq_eoi(&self, virq: u32) {
        let irq_desc = &self.irq_desc[virq as usize];

        self.chip(irq_desc.basic.ic_idx())
            .ic
            .irq_eoi(irq_desc.basic.ic_irq())
    }

    pub fn irq_enable(&self, virq: u32) {
        let irq_desc = &self.irq_desc[virq as usize];

        self.chip(irq_desc.basic.ic_idx())
            .ic
            .irq_enable(irq_desc.basic.ic_irq())
    }

    #[allow(unused)]
    pub fn irq_disable(&self, virq: u32) {
        let irq_desc = &self.irq_desc[virq as usize];

        self.chip(irq_desc.basic.ic_idx())
            .ic
            .irq_disable(irq_desc.basic.ic_irq())
    }

    #[cfg(target_arch = "riscv64")]
    pub fn irq_to_virq(&self, ic_idx: usize, hwirq: u32) -> Option<usize> {
        self.chip(ic_idx).ic.irq_to_virq(hwirq)
    }

    pub fn irq_xlate(&self, ic_idx: usize, irq_data: &[u32]) -> Result<usize, Error> {
        let irq_data = match irq_data.len() {
            1 => IrqCell::L1(irq_data[0]),
            2 => IrqCell::L2(irq_data[0], irq_data[1]),
            3 => IrqCell::L3(irq_data[0], irq_data[1], irq_data[2]),
            _ => return Err(Error::new(EINVAL)),
        };
        self.chip(ic_idx).ic.irq_xlate(irq_data)
    }

    pub fn trigger_virq(&self, virq: u32, token: &mut CleanLockToken) {
        if virq < 1024 {
            let desc = &self.irq_desc[virq as usize];
            match desc.handler() {
                Some(handler) => {
                    handler.irq_handler(virq, token);
                }
                _ => {
                    if let Some(ic_idx) = desc.basic.child_ic_idx() {
                        self.chip(ic_idx).ic.irq_handler(virq, token);
                    } else {
                        irq_trigger(virq as u8, token);
                    }
                }
            }
        }
    }

    pub fn phandle_to_ic_idx(&self, phandle: u32) -> Option<usize> {
        self.chips().iter().position(|x| x.phandle == phandle)
    }

    pub fn irq_iter_for(&self, ic_idx: u32) -> impl Iterator<Item = u8> + '_ {
        self.irq_desc.iter().filter_map(move |x| {
            if x.basic.ic_idx() == ic_idx as usize {
                Some(x.basic.ic_irq() as u8)
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
    IRQ_CHIP.irq_eoi(irq as u32);
}

const INIT_IRQ_DESC: IrqDesc = IrqDesc {
    basic: IrqDescItem {
        ic_idx: AtomicUsize::new(0),
        ic_irq: AtomicU32::new(0),
        child_ic_idx: AtomicUsize::new(NO_CHILD_IC),
        used: AtomicBool::new(false),
    },
    handler: Once::new(),
};

pub static IRQ_CHIP: IrqChipCore = IrqChipCore {
    chips: Once::new(),
    irq_desc: [INIT_IRQ_DESC; 1024],
};

/// Build the interrupt controller tree from the devicetree and publish it.
pub fn init(fdt: &Fdt) {
    travel_interrupt_ctrl(fdt);

    let mut list = IrqChipList { chips: Vec::new() };
    list.init_inner1(fdt);
    finish_init(list, Some(fdt));
}

/// Publish a controller list assembled by the platform (ACPI) instead of the
/// devicetree.
#[allow(dead_code)]
pub fn init_with_chips(chips: Vec<IrqChipItem>) {
    finish_init(IrqChipList { chips }, None);
}

fn finish_init(mut list: IrqChipList, fdt_opt: Option<&Fdt>) {
    if IRQ_CHIP.chips.is_completed() {
        error!("irqchip has already been initialized!");
        return;
    }

    let roots = list.init_inner2();
    list.init_inner3(fdt_opt, &IRQ_CHIP.irq_desc, roots);
    IRQ_CHIP.chips.call_once(|| list.chips.into_boxed_slice());
}

pub fn register_irq(virq: u32, handler: Box<dyn InterruptHandler>) {
    if virq >= 1024 {
        error!("irq {} exceed 1024!!!", virq);
        return;
    }

    let desc = &IRQ_CHIP.irq_desc[virq as usize];
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
/// add ordering. These helprs bridge the two ordering domains.
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
    if !IRQ_CHIP.irq_desc[index as usize].basic.try_set_used() {
        return false;
    }
    mmio_after_acquire();
    IRQ_CHIP.irq_enable(index as u32);
    true
}

/// Compatibility helper for users that still perform the reservation check
/// separately. New users should call [`try_set_reserved`] instead.
#[inline]
pub fn is_reserved(_cpu_id: LogicalCpuId, index: u8) -> bool {
    IRQ_CHIP.irq_desc[index as usize].basic.used()
}

/// Compatibility helper for users that still reserve in two steps. New users
/// should use [`try_set_reserved`] and [`free_reserved`] directly.
#[inline]
pub fn set_reserved(cpu_id: LogicalCpuId, index: u8, reserved: bool) {
    if reserved {
        let _ = try_set_reserved(cpu_id, index);
    } else {
        free_reserved(cpu_id, index);
    }
}

/// Release a reservation taken by [`try_set_reserved`].
///
/// The chip must be masked before the descriptor is handed back. Otherwise a
/// new owner could unmask it before this CPU masks it again. The release store
/// is the handoff point, so a later successful acquisition follows the mask.
#[inline]
pub fn free_reserved(_cpu_id: LogicalCpuId, index: u8) {
    IRQ_CHIP.irq_disable(index as u32);
    mmio_before_release();
    IRQ_CHIP.irq_desc[index as usize].basic.set_used(false);
}

pub fn available_irqs_iter(_cpu_id: LogicalCpuId) -> impl Iterator<Item = u8> + 'static {
    error!("available_irqs_iter has been called");
    0..0
}
