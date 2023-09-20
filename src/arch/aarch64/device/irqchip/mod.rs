use alloc::{boxed::Box, vec::Vec};
use syscall::Result;
use fdt::DeviceTree;

mod gic;

trait InterruptController {
    fn irq_init(&mut self, fdt: Option<&DeviceTree>) -> Result<()>;
    fn irq_ack(&mut self) -> u32;
    fn irq_eoi(&mut self, irq_num: u32);
    fn irq_enable(&mut self, irq_num: u32);
    fn irq_disable(&mut self, irq_num: u32);
}

struct IrqChipCore {
    //TODO: support multi level interrupt constrollers
    ic: Vec<Box<dyn InterruptController>>,
    main_ic_idx: usize,
}

impl IrqChipCore {
    pub fn irq_ack(&mut self) -> u32 {
        self.ic[self.main_ic_idx].irq_ack()
    }

    pub fn irq_eoi(&mut self, irq_num: u32) {
        self.ic[self.main_ic_idx].irq_eoi(irq_num)
    }

    pub fn irq_enable(&mut self, irq_num: u32) {
        self.ic[self.main_ic_idx].irq_enable(irq_num)
    }

    pub fn irq_disable(&mut self, irq_num: u32) {
        self.ic[self.main_ic_idx].irq_disable(irq_num)
    }
}

static IRQ_CHIP = IrqChipCore { ic: Vec::new(), main_ic_idx: 0 };

pub fn init(fdt: Option<&DeviceTree>) {
    let ic = Box::new(gic::GenericInterruptController::new());
    let irq_chip_core =  IrqChipCore { ic };
}
