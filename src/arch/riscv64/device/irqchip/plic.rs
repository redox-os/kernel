use crate::{
    arch::{device::irqchip::hlic, start::BOOT_HART_ID},
    dtb::irqchip::{InterruptController, InterruptHandler, IrqDesc, IRQ_CHIP},
};
use core::{mem, num::NonZero, sync::atomic::Ordering};
use fdt::Fdt;
use log::{error, info};
use syscall::{Error, Io, Mmio, ENODEV};

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
const _: () = assert!(0x1000 == mem::size_of::<InterruptThresholdRegs>());

impl PlicRegs {
    pub fn set_priority(self: &mut Self, irq: usize, priority: usize) {
        assert!(irq > 0 && irq <= 1023 && priority < 8);
        self.source_priority[irq].write(priority as u32);
    }

    pub fn pending(self: &Self, irq_lane: usize) -> u32 {
        assert!(irq_lane < 32);
        self.pending[irq_lane].read()
    }

    pub fn enable(self: &mut Self, context: usize, irq: NonZero<usize>, enable: bool) {
        assert!(irq.get() <= 1023 && context < MAX_CONTEXTS);
        let irq_lane = irq.get() / 32;
        let irq = irq.get() % 32;
        self.enable[context][irq_lane].writef(1u32 << irq, enable);
    }

    pub fn set_priority_threshold(self: &mut Self, context: usize, priority: usize) {
        assert!(context < MAX_CONTEXTS && priority <= 7);
        self.thresholds[context].threshold.write(priority as u32);
    }

    pub fn claim(self: &mut Self, context: usize) -> Option<NonZero<usize>> {
        assert!(context < MAX_CONTEXTS);
        let claim = self.thresholds[context].claim_complete.read();
        NonZero::new(claim as usize)
    }

    pub fn complete(self: &mut Self, context: usize, claim: NonZero<usize>) {
        assert!(context < MAX_CONTEXTS);
        self.thresholds[context]
            .claim_complete
            .write(claim.get() as u32);
    }
}

pub struct Plic {
    regs: *mut PlicRegs,
    ndev: usize,
    virq_base: usize,
    context: usize,
}

impl Plic {
    pub fn new() -> Self {
        Self {
            regs: 0 as *mut PlicRegs,
            ndev: 0,
            virq_base: 0,
            context: 0,
        }
    }
}
impl InterruptHandler for Plic {
    fn irq_handler(&mut self, _irq: u32) {
        unsafe {
            let irq = self.irq_ack();
            //println!("PLIC interrupt {}", irq);
            if let Some(virq) = self.irq_to_virq(irq) {
                IRQ_CHIP.trigger_virq(virq as u32);
            } else {
                error!("unexpected irq num {}", irq);
                self.irq_eoi(irq);
            }
        }
        //println!("PLIC interrupt done");
    }
}

impl InterruptController for Plic {
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> syscall::Result<()> {
        let desc = unsafe { &IRQ_CHIP.irq_chip_list.chips[ic_idx] };
        let fdt = fdt_opt.unwrap();
        let my_node = fdt.find_phandle(desc.phandle).unwrap();

        // MMIO region
        let reg = my_node.reg().unwrap().next().unwrap();
        // Specifies how many external interrupts are supported by this controller.
        let ndev = my_node
            .property("riscv,ndev")
            .and_then(|x| x.as_usize())
            .unwrap();

        unsafe {
            self.regs = reg.starting_address.add(crate::PHYS_OFFSET) as *mut PlicRegs;
        }
        self.ndev = ndev;

        self.virq_base = *irq_idx;
        for i in 0..ndev {
            irq_desc[self.virq_base + i].basic.ic_idx = ic_idx;
            irq_desc[self.virq_base + i].basic.ic_irq = i as u32;
        }
        *irq_idx += ndev;

        // route all interrupts to boot HART
        // TODO spread irqs over all the cores when we have them?
        let hlic_ic_idx = hlic::irqchip_for_hart(BOOT_HART_ID.load(Ordering::Relaxed))
            .expect("Could not find HLIC irqchip for the boot hart while initing PLIC");
        self.context = desc
            .parents
            .iter()
            .position(|x| x.parent_interrupt[0] != u32::MAX && x.parent == hlic_ic_idx)
            .unwrap();
        info!("PLIC: using context {}", self.context);

        let regs = unsafe { self.regs.as_mut().unwrap() };
        regs.set_priority_threshold(self.context, 0);

        Ok(())
    }

    fn irq_ack(&mut self) -> u32 {
        let regs = unsafe { self.regs.as_mut().unwrap() };
        regs.claim(self.context).unwrap().get() as u32
    }

    fn irq_eoi(&mut self, irq_num: u32) {
        let regs = unsafe { self.regs.as_mut().unwrap() };
        regs.complete(self.context, NonZero::new(irq_num as usize).unwrap());
    }

    fn irq_enable(&mut self, irq_num: u32) {
        assert!(irq_num > 0 && irq_num as usize <= self.ndev);
        let regs = unsafe { self.regs.as_mut().unwrap() };
        regs.set_priority(irq_num as usize, 1);
        regs.enable(self.context, NonZero::new(irq_num as usize).unwrap(), true);
    }

    fn irq_disable(&mut self, irq_num: u32) {
        assert!(irq_num > 0 && irq_num as usize <= self.ndev);
        let regs = unsafe { self.regs.as_mut().unwrap() };
        regs.set_priority(irq_num as usize, 1);
        regs.enable(self.context, NonZero::new(irq_num as usize).unwrap(), false);
    }

    fn irq_xlate(&self, irq_data: &[u32; 3]) -> syscall::Result<usize> {
        if (irq_data[0] as usize) < self.ndev {
            Ok(self.virq_base + irq_data[0] as usize)
        } else {
            Err(Error::new(ENODEV))
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
