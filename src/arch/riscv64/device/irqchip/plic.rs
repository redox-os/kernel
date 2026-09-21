use crate::{
    arch::{device::irqchip::hlic, start::BOOT_HART_ID},
    dtb::{
        get_mmio_address,
        irqchip::{
            mmio_after_acquire, mmio_before_release, InterruptController, InterruptHandler,
            IrqCell, IrqChipItem, IrqDesc, IRQ_CHIP,
        },
    },
    sync::CleanLockToken,
};
use core::{mem, num::NonZero, ptr, sync::atomic::Ordering};
use fdt::Fdt;
use spin::Mutex;
use syscall::{Error, Mmio, EINVAL};

#[repr(packed(4))]
#[repr(C)]
struct InterruptThresholdRegs {
    threshold: Mmio<u32>,
    claim_complete: Mmio<u32>,
    _rsrv: [u32; 1022],
}

static MAX_CONTEXTS: usize = 64;

#[repr(packed(4))]
#[repr(C)]
struct PlicRegs {
    /// source priorities
    source_priority: [Mmio<u32>; 1024], // +0000 -- 0fff
    // pending interrupts
    pending: [Mmio<u32>; 1024], // +1000 -- 1fff
    // per-context interrupt enable
    enable: [[Mmio<u32>; 32]; 16320], // +2000 - 1f'ffff
    // per-context priority threshold and acknowledge
    thresholds: [InterruptThresholdRegs; 64], // specced at +20'0000 - 0fff'ffff for 15872 contexts
                                              // but actual memory allotted in firmware is much lower
}

const _: () = assert!(0x1000 == mem::offset_of!(PlicRegs, pending));
const _: () = assert!(0x2000 == mem::offset_of!(PlicRegs, enable));
const _: () = assert!(0x20_0000 == mem::offset_of!(PlicRegs, thresholds));
const _: () = assert!(0x1000 == size_of::<InterruptThresholdRegs>());

pub struct Plic {
    regs: *mut PlicRegs,
    ndev: usize,
    virq_base: usize,
    context: usize,
    enable_lock: Mutex<()>,
}

// SAFETY: `regs` points at the PLIC's device memory, which is shared by every
// hart by design. It is never turned into a reference. The accessors below go
// through raw volatile reads and writes, so concurrent access from two harts
// is a hardware question and not `&mut` aliasing. The one register that has to
// be read-modify-written, the per-context enable word, is serialized by
// `enable_lock`. Everything else is a single load or store of one word.
unsafe impl Send for Plic {}
unsafe impl Sync for Plic {}

impl Plic {
    pub fn new() -> Self {
        Self {
            regs: 0 as *mut PlicRegs,
            ndev: 0,
            virq_base: 0,
            context: 0,
            enable_lock: Mutex::new(()),
        }
    }

    /// Panics if `irq_init` has not mapped the registers yet.
    #[inline]
    fn regs(&self) -> *mut PlicRegs {
        assert!(!self.regs.is_null(), "PLIC registers are not mapped yet");
        self.regs
    }

    /// # Safety
    ///
    /// `cell` must point at one of this PLIC's register cells.
    ///
    /// `Mmio<u32>` is `repr(transparent)` over the word itself, so this is the
    /// same access `Io::read` would perform, without taking a reference that
    /// would alias another hart's.
    #[inline]
    unsafe fn read_cell(cell: *mut Mmio<u32>) -> u32 {
        unsafe { ptr::read_volatile(cell.cast::<u32>()) }
    }

    /// # Safety
    ///
    /// `cell` must point at one of this PLIC's register cells.
    #[inline]
    unsafe fn write_cell(cell: *mut Mmio<u32>, value: u32) {
        unsafe { ptr::write_volatile(cell.cast::<u32>(), value) }
    }

    fn set_priority(&self, irq: usize, priority: usize) {
        assert!(irq > 0 && irq <= 1023 && priority < 8);
        unsafe {
            Self::write_cell(
                &raw mut (*self.regs()).source_priority[irq],
                priority as u32,
            );
        }
    }

    fn set_enabled(&self, context: usize, irq: NonZero<usize>, enable: bool) {
        assert!(irq.get() <= 1023 && context < MAX_CONTEXTS);
        let irq_lane = irq.get() / 32;
        let bit = 1u32 << (irq.get() % 32);

        let _guard = self.enable_lock.lock();

        mmio_after_acquire();
        unsafe {
            let cell = &raw mut (*self.regs()).enable[context][irq_lane];
            let old = Self::read_cell(cell);
            let new = if enable { old | bit } else { old & !bit };
            if new != old {
                Self::write_cell(cell, new);
            }
        }
        mmio_before_release();
    }

    fn set_priority_threshold(&self, context: usize, priority: usize) {
        assert!(context < MAX_CONTEXTS && priority <= 7);
        unsafe {
            Self::write_cell(
                &raw mut (*self.regs()).thresholds[context].threshold,
                priority as u32,
            );
        }
    }

    fn claim(&self, context: usize) -> Option<NonZero<usize>> {
        assert!(context < MAX_CONTEXTS);
        let claim =
            unsafe { Self::read_cell(&raw mut (*self.regs()).thresholds[context].claim_complete) };
        NonZero::new(claim as usize)
    }

    fn complete(&self, context: usize, claim: NonZero<usize>) {
        assert!(context < MAX_CONTEXTS);
        unsafe {
            Self::write_cell(
                &raw mut (*self.regs()).thresholds[context].claim_complete,
                claim.get() as u32,
            );
        }
    }
}

impl InterruptHandler for Plic {
    fn irq_handler(&self, _irq: u32, token: &mut CleanLockToken) {
        let irq = self.irq_ack();
        //println!("PLIC interrupt {}", irq);
        if let Some(virq) = self.irq_to_virq(irq) {
            IRQ_CHIP.trigger_virq(virq as u32, token);
        } else {
            error!("unexpected irq num {}", irq);
            self.irq_eoi(irq);
        }
        //println!("PLIC interrupt done");
    }
}

impl InterruptController for Plic {
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &[IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
        chips: &[IrqChipItem],
    ) -> syscall::Result<()> {
        let desc = &chips[ic_idx];
        let fdt = fdt_opt.unwrap();
        let my_node = fdt.find_phandle(desc.phandle).unwrap();

        // MMIO region
        let reg = my_node.reg().unwrap().next().unwrap();
        let addr = get_mmio_address(&fdt, &my_node, &reg).unwrap();
        // Specifies how many external interrupts are supported by this controller.
        let ndev = my_node
            .property("riscv,ndev")
            .and_then(|x| x.as_usize())
            .unwrap();

        self.regs = (addr + crate::PHYS_OFFSET) as *mut PlicRegs;
        self.ndev = ndev;

        self.virq_base = *irq_idx;
        for i in 0..ndev {
            irq_desc[self.virq_base + i]
                .basic
                .set_mapping(ic_idx, i as u32);
        }
        *irq_idx += ndev;

        // route all interrupts to boot HART
        // TODO spread irqs over all the cores when we have them?
        let hlic_ic_idx = hlic::irqchip_for_hart(BOOT_HART_ID.load(Ordering::Relaxed))
            .expect("Could not find HLIC irqchip for the boot hart while initing PLIC");
        self.context = desc
            .parents
            .iter()
            .position(|x| x.parent_interrupt.is_some() && x.parent == hlic_ic_idx)
            .unwrap();
        info!("PLIC: using context {}", self.context);

        self.set_priority_threshold(self.context, 0);

        Ok(())
    }

    fn irq_ack(&self) -> u32 {
        self.claim(self.context).unwrap().get() as u32
    }

    fn irq_eoi(&self, irq_num: u32) {
        self.complete(self.context, NonZero::new(irq_num as usize).unwrap());
    }

    fn irq_enable(&self, irq_num: u32) {
        assert!(irq_num > 0 && irq_num as usize <= self.ndev);
        self.set_priority(irq_num as usize, 1);
        self.set_enabled(self.context, NonZero::new(irq_num as usize).unwrap(), true);
    }

    fn irq_disable(&self, irq_num: u32) {
        assert!(irq_num > 0 && irq_num as usize <= self.ndev);
        self.set_priority(irq_num as usize, 1);
        self.set_enabled(self.context, NonZero::new(irq_num as usize).unwrap(), false);
    }

    fn irq_xlate(&self, irq_data: IrqCell) -> syscall::Result<usize> {
        match irq_data {
            IrqCell::L1(irq) => Ok(self.virq_base + irq as usize),
            _ => Err(Error::new(EINVAL)),
        }
    }

    fn irq_to_virq(&self, hwirq: u32) -> Option<usize> {
        if (hwirq as usize) < self.ndev {
            Some(self.virq_base + hwirq as usize)
        } else {
            None
        }
    }
}
