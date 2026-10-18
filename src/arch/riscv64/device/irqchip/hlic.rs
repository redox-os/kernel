use crate::{
    arch::device::ArchPercpuMisc,
    dtb::irqchip::{
        InterruptController, InterruptHandler, IrqCell, IrqChip, IrqConnection, IrqDesc,
    },
    percpu::PercpuBlock,
    sync::CleanLockToken,
};
use core::arch::asm;
use fdt::Fdt;
use syscall::{Error, EINVAL};

// This is a hart-local interrupt controller, a root of irqchip tree
// An example DTS:
// /cpus/
//    cpu@1/
//      interrupt-controller/
//        #interrupt-cells = 0x00000001
//        interrupt-controller =
//        compatible = "riscv,cpu-intc"
//        phandle = 0x00000006

unsafe fn acknowledge(interrupt: usize) {
    unsafe {
        asm!(
        "csrc sip, t0",
        in("t0") 1usize << interrupt,
        options(nostack)
        )
    }
}

pub unsafe fn enable_local_interrupts() {
    unsafe {
        asm!(
            "csrs sie, t0",
            in("t0") (0xFFFF),
            options(nostack)
        )
    }
}
// is it actually necessary to expose individual local interrupts to userspace?
// we could remove a lot of overhead by hard-wiring these until the plic/...
//
// the previous and current implementation does not actually propagate these
// to userspace at all anyway since the hlic's handler is never called.
#[inline(always)]
pub unsafe fn interrupt(interrupt: usize, token: &mut CleanLockToken) {
    unsafe {
        acknowledge(interrupt);

        let ArchPercpuMisc {
            hart_id,
            ref hlic_idx,
        } = PercpuBlock::current().misc_arch_info;

        let virq = IrqChip::irq_to_virq(
            hlic_idx
                .get()
                .copied()
                .expect("Interrupt before hlic_idx is initialized!"),
            interrupt as u32,
        )
        .unwrap_or_else(|| panic!("HLIC doesn't know of interrupt {}", interrupt));

        let IrqDesc { basic, handler } = &IrqChip::descs()[virq];
        // per-hart direct handler for software (sbi ipi), timer, external
        // and counter overflow interrupts
        if let Some(handler) = handler.get() {
            handler.irq_handler(virq as u32, token);
        // propagate interrupt to child
        // eg. clic, plic, imsic,  aplic
        } else if let Some(ic_idx) = basic.child_ic_idx {
            IrqChip::chips()[ic_idx].ic.irq_handler(virq as u32, token);
        } else {
            panic!(
                "Unconnected interrupt {} occurred on hlic connected to hart {}",
                interrupt, hart_id
            );
        }
    }
}

pub struct Hlic {
    virq_base: usize,
}

impl Hlic {
    pub(crate) fn new() -> Self {
        Self { virq_base: 0 }
    }
}
// never actually used as the the above interrupt function either
// invokes the handler on desc or of its child.
impl InterruptHandler for Hlic {
    unsafe fn irq_handler(&self, irq: u32, token: &mut CleanLockToken) {
        assert!(irq < 16, "Unsupported HLIC interrupt raised!");
        unsafe {
            IrqChip::trigger_virq(self.virq_base as u32 + irq, token);
        }
    }
}

impl InterruptController for Hlic {
    unsafe fn irq_init(
        &mut self,
        _fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
        _phandle: u32,
        _parents: &[IrqConnection],
    ) -> syscall::Result<()> {
        self.virq_base = *irq_idx;
        for i in 0..16 {
            irq_desc[self.virq_base + i].basic.ic_idx = ic_idx;
            irq_desc[self.virq_base + i].basic.ic_irq = i as u32;
        }
        *irq_idx += 16;
        Ok(())
    }

    unsafe fn irq_ack(&self) -> u32 {
        panic!("Cannot ack HLIC interrupt");
    }

    unsafe fn irq_eoi(&self, _irq_num: u32) {}

    unsafe fn irq_enable(&self, _irq_num: u32) {
        // This would require IPI to a correct core
        // Not bothering with this, all interrupts are enabled at all times
    }

    unsafe fn irq_disable(&self, _irq_num: u32) {
        // This would require IPI to a correct core
        // Not bothering with this, all interrupts are enabled at all times
    }

    fn irq_xlate(&self, irq_data: IrqCell) -> syscall::Result<usize> {
        match irq_data {
            IrqCell::L1(irq) if irq <= 0xF => Ok(self.virq_base + irq as usize),
            _ => Err(Error::new(EINVAL)),
        }
    }

    fn irq_to_virq(&self, hwirq: u32) -> Option<usize> {
        if hwirq > 0 && hwirq <= 0xF {
            Some(self.virq_base + hwirq as usize)
        } else {
            None
        }
    }
}
