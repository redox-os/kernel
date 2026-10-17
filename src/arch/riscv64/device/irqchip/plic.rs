use crate::{
    dtb::{
        get_mmio_address,
        irqchip::{
            InterruptController, InterruptHandler, IrqCell, IrqChip, IrqConnection, IrqDesc,
        },
    },
    percpu::PercpuBlock,
    sync::CleanLockToken,
};
use alloc::boxed::Box;
use core::{
    cell::SyncUnsafeCell,
    mem,
    num::{NonZero, NonZeroUsize},
};
use fdt::Fdt;
use syscall::{Error, Io, Mmio, EINVAL};

#[repr(packed(4))]
#[repr(C)]
struct InterruptThresholdRegs {
    threshold: Mmio<u32>,
    claim_complete: Mmio<u32>,
    _rsrv: [u32; 1022],
}

static MAX_CONTEXTS: usize = 64;

const SUPERVISOR_EXTERNAL_INTERRUPT: u32 = 9;

#[repr(packed(4))]
#[repr(C)]
struct PlicRegs {
    /// source priorities
    source_priority: [SyncUnsafeCell<Mmio<u32>>; 1024], // +0000 -- 0fff
    // pending interrupts
    pending: [Mmio<u32>; 1024], // +1000 -- 1fff
    // per-context interrupt enable
    enable: [SyncUnsafeCell<[Mmio<u32>; 32]>; 16320], // +2000 - 1f'ffff
    // per-context priority threshold and acknowledge
    thresholds: [SyncUnsafeCell<InterruptThresholdRegs>; 64], // specced at +20'0000 - 0fff'ffff for 15872 contexts
                                                              // but actual memory allotted in firmware is much lower
}

const _: () = assert!(0x1000 == mem::offset_of!(PlicRegs, pending));
const _: () = assert!(0x2000 == mem::offset_of!(PlicRegs, enable));
const _: () = assert!(0x20_0000 == mem::offset_of!(PlicRegs, thresholds));
const _: () = assert!(0x1000 == size_of::<InterruptThresholdRegs>());

impl PlicRegs {
    unsafe fn set_priority(&self, irq: u32, priority: usize) {
        unsafe {
            assert!(irq > 0 && irq <= 1023 && priority < 8);
            self.source_priority[irq as usize]
                .get()
                .as_mut_unchecked()
                .write(priority as u32);
        }
    }

    fn pending(&self, irq_lane: usize) -> u32 {
        assert!(irq_lane < 32);
        self.pending[irq_lane].read()
    }

    unsafe fn enable(&self, context: NonZero<usize>, irq: NonZero<u32>, enable: bool) {
        unsafe {
            assert!(irq.get() <= 1023 && context.get() < MAX_CONTEXTS);
            let irq_lane = irq.get() as usize / 32;
            let irq = irq.get() as usize % 32;
            self.enable[context.get()].get().as_mut_unchecked()[irq_lane]
                .writef(1u32 << irq, enable);
        }
    }

    unsafe fn set_priority_threshold(&self, context: NonZero<usize>, priority: u32) {
        unsafe {
            assert!(context.get() < MAX_CONTEXTS && priority <= 7);
            self.thresholds[context.get()]
                .get()
                .as_mut_unchecked()
                .threshold
                .write(priority as u32);
        }
    }

    unsafe fn claim(&self, context: NonZero<usize>) -> Option<NonZero<u32>> {
        unsafe {
            assert!(context.get() < MAX_CONTEXTS);
            let claim = self.thresholds[context.get()]
                .get()
                .as_ref_unchecked()
                .claim_complete
                .read();
            NonZero::new(claim)
        }
    }

    unsafe fn complete(&self, context: NonZero<usize>, claim: NonZero<u32>) {
        unsafe {
            assert!(context.get() < MAX_CONTEXTS);
            self.thresholds[context.get()]
                .get()
                .as_mut_unchecked()
                .claim_complete
                .write(claim.get());
        }
    }
}

pub struct Plic {
    regs: *const PlicRegs,
    ndev: usize,
    virq_base: usize,
    // the zeroth context would always be for machine mode
    supervisor_context_per_hart: Box<[Option<NonZeroUsize>]>,
}

impl Plic {
    pub fn new() -> Self {
        Self {
            regs: core::ptr::null_mut(),
            ndev: 0,
            virq_base: 0,
            supervisor_context_per_hart: Box::new([]),
        }
    }
    pub fn local_context(&self) -> NonZero<usize> {
        self.supervisor_context_per_hart
            .get(PercpuBlock::current_hart())
            .and_then(|c| *c)
            .expect("PLIC local_context called w")
    }
}
impl InterruptHandler for Plic {
    unsafe fn irq_handler(&self, irq: u32, token: &mut CleanLockToken) {
        unsafe {
            let irq @ 1.. = self.irq_ack() else {
                info!(
                    "PLIC context {}, irq {} already claimed",
                    self.local_context(),
                    irq
                );
                return;
            };
            if let Some(virq) = self.irq_to_virq(irq) {
                IrqChip::trigger_virq(virq as u32, token);
            } else {
                error!("unexpected irq num {}", irq);
                self.irq_eoi(irq);
            }
        }
        //println!("PLIC interrupt done");
    }
}

impl InterruptController for Plic {
    unsafe fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
        phandle: u32,
        parents: &[IrqConnection],
    ) -> syscall::Result<()> {
        let fdt = fdt_opt.unwrap();
        let my_node = fdt.find_phandle(phandle).unwrap();

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
            irq_desc[self.virq_base + i].basic.ic_idx = ic_idx;
            irq_desc[self.virq_base + i].basic.ic_irq = i as u32;
        }
        *irq_idx += ndev;

        // route all interrupts to boot HART
        // TODO spread irqs over all the cores when we have them?
        self.supervisor_context_per_hart = fdt
            .find_all_nodes("/cpus/cpu")
            .enumerate()
            .map(|(i, c)| {
                let hlic = c
                    .children()
                    .find(|h| {
                        h.compatible()
                            .is_some_and(|comp| comp.all().any(|comp| comp == "riscv,cpu-intc"))
                    })
                    .expect("PLIC failed to find hlic for hart in dtb!");
                assert_eq!(
                    i,
                    str::parse::<usize>(&c.name[4..]).unwrap_or_else(|_| panic!(
                        "PLIC failed to parse hart_id of cpu node! \n name: \"{}\"",
                        c.name
                    )),
                    "Inconsistent hart_id / position in dtb!"
                );
                parents
                    .iter()
                    .position(|con| {
                        matches!(
                            con.parent_interrupt,
                            // Specify supervisor external interrupt to account for M mode contexts
                            Some(IrqCell::L1(SUPERVISOR_EXTERNAL_INTERRUPT))
                        ) && con.parent_phandle
                            == hlic
                                .property("phandle")
                                .and_then(|p| p.as_usize())
                                .expect("PLIC failed to parse phandle of hlic!")
                                as u32
                    })
                    .map(|pos| {
                        NonZeroUsize::new(pos).expect("PLIC supervisor context in zeroth position!")
                    })
            })
            .collect();

        info!(
            "PLIC: contexts {:?}\nBoot context: {}",
            self.supervisor_context_per_hart,
            self.local_context()
        );

        unsafe {
            for context in self.supervisor_context_per_hart.iter().filter_map(|c| *c) {
                self.regs
                    .as_ref_unchecked()
                    .set_priority_threshold(context, 0);
            }
        }

        Ok(())
    }

    /// Return zero if the interrupt has already been claimed
    unsafe fn irq_ack(&self) -> u32 {
        unsafe {
            let regs = self.regs.as_ref().unwrap();
            regs.claim(self.local_context()).map_or(0, NonZero::get)
        }
    }

    unsafe fn irq_eoi(&self, irq_num: u32) {
        unsafe {
            let regs = self.regs.as_ref().unwrap();
            regs.complete(self.local_context(), NonZero::new(irq_num).unwrap());
        }
    }

    unsafe fn irq_enable(&self, irq_num: u32) {
        unsafe {
            assert!(irq_num > 0 && irq_num as usize <= self.ndev);
            let regs = self.regs.as_ref().unwrap();
            regs.set_priority(irq_num, 1);
            regs.enable(self.local_context(), NonZero::new(irq_num).unwrap(), true);
        }
    }

    unsafe fn irq_disable(&self, irq_num: u32) {
        unsafe {
            assert!(irq_num > 0 && irq_num as usize <= self.ndev);
            let regs = self.regs.as_ref().unwrap();
            regs.set_priority(irq_num, 1);
            regs.enable(self.local_context(), NonZero::new(irq_num).unwrap(), false);
        }
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
