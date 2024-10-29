use fdt::Fdt;
use syscall::{
    error::{Error, EINVAL},
    Result,
};

use super::InterruptController;
use crate::dtb::irqchip::{InterruptHandler, IrqDesc};

pub struct Null;

impl InterruptHandler for Null {
    fn irq_handler(&mut self, _irq: u32) {}
}

impl InterruptController for Null {
    fn irq_init(
        &mut self,
        fdt: &Fdt,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> Result<()> {
        Ok(())
    }
    fn irq_ack(&mut self) -> u32 {
        unimplemented!()
    }
    fn irq_eoi(&mut self, irq_num: u32) {
    }
    fn irq_enable(&mut self, irq_num: u32) {
    }
    fn irq_disable(&mut self, irq_num: u32) {
    }
    fn irq_xlate(&self, irq_data: &[u32; 3]) -> Result<usize> {
        Err(Error::new(EINVAL))
    }
    fn irq_to_virq(&self, hwirq: u32) -> Option<usize> {
        None
    }
}