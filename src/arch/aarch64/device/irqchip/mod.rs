use alloc::{boxed::Box, vec::Vec};
use syscall::Result;
use fdt::DeviceTree;

mod gic;
mod irq_bcm2835;
mod irq_bcm2836;

pub trait InterruptController {
    fn irq_init(&mut self, fdt: Option<&DeviceTree>) -> Result<()>;
    fn irq_ack(&mut self) -> u32;
    fn irq_eoi(&mut self, irq_num: u32);
    fn irq_enable(&mut self, irq_num: u32);
    fn irq_disable(&mut self, irq_num: u32);
}

pub trait InterruptHandler {
    fn irq_handler(&mut self, irq: u32);
}

pub struct IrqChipCore {
    //TODO: support multi level interrupt constrollers
    pub ic: Vec<Box<dyn InterruptController>>,
    pub ic_idx: usize,
    pub handlers: [Option<Box<dyn InterruptHandler>>; 1024],
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

const INIT_HANDLER: Option<Box<dyn InterruptHandler>> = None;
pub static mut IRQ_CHIP: IrqChipCore = IrqChipCore { 
    ic: Vec::new(),
    ic_idx: 0,
    handlers: [INIT_HANDLER; 1024],
};

pub fn init(fdt: Option<&DeviceTree>) {
    unsafe {
         let ic = Box::new(gic::GenericInterruptController::new());
         IRQ_CHIP.ic.push(ic); 
         let ic = Box::new(irq_bcm2836::Bcm2836ArmInterruptController::new());
         IRQ_CHIP.ic.push(ic); 
         for ic in IRQ_CHIP.ic.iter_mut() {
             let _ = ic.irq_init(fdt);
         }
    }
}

pub fn register_irq(irq: u32, handler: Box<dyn InterruptHandler>) {
    if irq >= 1024 {
        println!("irq {} exceed 1024!!!", {irq});
        return ;
    }

    unsafe {
        if let Some(_) = IRQ_CHIP.handlers[irq as usize] {
            println!("irq {} has already been registered!", irq);
            return ;
        }

        IRQ_CHIP.handlers[irq as usize] = Some(handler);
    }
}
