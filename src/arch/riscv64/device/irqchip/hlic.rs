use crate::dtb::irqchip::{InterruptController, InterruptHandler, IrqDesc, IRQ_CHIP};
use alloc::vec::Vec;
use core::arch::asm;
use fdt::{node::NodeProperty, Fdt};
use syscall::{Error, ENOENT};

// This is a hart-local interrupt controller, a root of irqchip tree
// An example DTS:
// /cpus/
//    cpu@1/
//      interrupt-controller/
//        #interrupt-cells = 0x00000001
//        interrupt-controller =
//        compatible = "riscv,cpu-intc"
//        phandle = 0x00000006

fn acknowledge(interrupt: usize) {
    unsafe {
        asm!(
        "csrc sip, t0",
        in("t0") 1usize << interrupt,
        options(nostack)
        )
    }
}

pub unsafe fn interrupt(hart: usize, interrupt: usize) {
    assert!(
        hart < CPU_INTERRUPT_HANDLERS.len(),
        "Unexpected hart in interrupt routine"
    );
    acknowledge(interrupt);
    let ic_idx = CPU_INTERRUPT_HANDLERS[hart].unwrap_or_else(|| {
        panic!(
            "No hlic connected to hart {} yet interrupt {} occurred",
            hart, interrupt
        )
    });
    let virq = IRQ_CHIP
        .irq_to_virq(ic_idx, interrupt as u32)
        .unwrap_or_else(|| panic!("HLIC doesn't know of interrupt {}", interrupt));
    if let Some(handler) = &mut IRQ_CHIP.irq_desc[virq].handler {
        handler.irq_handler(virq as u32);
    } else if let Some(ic_idx) = IRQ_CHIP.irq_desc[virq].basic.child_ic_idx {
        IRQ_CHIP.irq_chip_list.chips[ic_idx]
            .ic
            .irq_handler(virq as u32);
    } else {
        panic!(
            "Unconnected interrupt {} occurred on hlic connected to hart {}",
            interrupt, hart
        );
    }
}

pub fn init() {
    unsafe {
        asm!(
            "csrs sie, t0",
            in("t0") (0xFFFF),
            options(nostack)
        )
    }
}

static mut CPU_INTERRUPT_HANDLERS: Vec<Option<usize>> = Vec::new();

pub struct Hlic {
    virq_base: usize,
}

impl Hlic {
    pub(crate) fn new() -> Self {
        return Self { virq_base: 0 };
    }
}
impl InterruptHandler for Hlic {
    fn irq_handler(&mut self, irq: u32) {
        assert!(irq < 16, "Unsupported HLIC interrupt raised!");
        unsafe {
            IRQ_CHIP.trigger_virq(self.virq_base as u32 + irq);
        }
    }
}

impl InterruptController for Hlic {
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> syscall::Result<()> {
        let desc = unsafe { &IRQ_CHIP.irq_chip_list.chips[ic_idx] };
        let fdt = fdt_opt.unwrap();
        let cpu_node = fdt
            .find_all_nodes("/cpus/cpu")
            .find(|x| {
                x.children().any(|x| {
                    x.property("phandle").and_then(NodeProperty::as_usize)
                        == Some(desc.phandle as usize)
                })
            })
            .expect("Could not find CPU node for HLIC controller");
        let hart = cpu_node.property("reg").unwrap().as_usize().unwrap();
        unsafe {
            if CPU_INTERRUPT_HANDLERS.len() <= hart {
                CPU_INTERRUPT_HANDLERS.resize(hart + 1, None);
            }
            assert!(
                CPU_INTERRUPT_HANDLERS[hart].replace(ic_idx).is_none(),
                "Conflicting HLIC interrupt handler found"
            );
        }
        self.virq_base = *irq_idx;
        for i in 0..16 {
            irq_desc[self.virq_base + i].basic.ic_idx = ic_idx;
            irq_desc[self.virq_base + i].basic.ic_irq = i as u32;
        }
        *irq_idx += 16;
        Ok(())
    }

    fn irq_ack(&mut self) -> u32 {
        panic!("Cannot ack HLIC interrupt");
    }

    fn irq_eoi(&mut self, _irq_num: u32) {}

    fn irq_enable(&mut self, _irq_num: u32) {
        // This would require IPI to a correct core
        // Not bothering with this, all interrupts are enabled at all times
    }

    fn irq_disable(&mut self, _irq_num: u32) {
        // This would require IPI to a correct core
        // Not bothering with this, all interrupts are enabled at all times
    }

    fn irq_xlate(&self, irq_data: &[u32; 3]) -> syscall::Result<usize> {
        let irq = irq_data[0];
        match irq {
            0..=0xF => Ok(self.virq_base + irq as usize),
            _ => Err(Error::new(ENOENT)),
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

pub fn irqchip_for_hart(hart: usize) -> Option<usize> {
    let value = unsafe { CPU_INTERRUPT_HANDLERS.get(hart) }?;
    *value
}
