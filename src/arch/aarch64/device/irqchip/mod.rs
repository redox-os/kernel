use alloc::{boxed::Box, vec::Vec};
use syscall::Result;
use fdt::DeviceTree;

mod gic;

pub trait InterruptController {
    fn irq_init(&mut self, fdt: Option<&DeviceTree>) -> Result<()>;
    fn irq_ack(&mut self) -> u32;
    fn irq_eoi(&mut self, irq_num: u32);
    fn irq_enable(&mut self, irq_num: u32);
    fn irq_disable(&mut self, irq_num: u32);
}

pub struct IrqChipCore {
    //TODO: support multi level interrupt constrollers
    pub ic: Vec<Box<dyn InterruptController>>,
    pub ic_idx: usize,
}

impl IrqChipCore {
    pub fn irq_ack(&mut self) -> u32 {
        self.ic[self.ic_idx].irq_ack()
    }

    pub fn irq_eoi(&mut self, irq_num: u32) {
        self.ic[self.ic_idx].irq_eoi(irq_num)
    }

    pub fn irq_enable(&mut self, irq_num: u32) {
        self.ic[self.ic_idx].irq_enable(irq_num)
    }

    pub fn irq_disable(&mut self, irq_num: u32) {
        self.ic[self.ic_idx].irq_disable(irq_num)
    }
}

pub static mut IRQ_CHIP: IrqChipCore = IrqChipCore { ic: Vec::new(), ic_idx: 0 };

pub fn init(fdt: Option<&DeviceTree>) {
    let ic = Box::new(gic::GenericInterruptController::new());
    unsafe {
         IRQ_CHIP.ic.push(ic); 
         for ic in IRQ_CHIP.ic.iter_mut() {
             ic.irq_init(fdt).unwrap();
         }
    }
}
