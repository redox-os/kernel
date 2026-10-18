use fdt::Fdt;
use syscall::{
    error::{Error, EINVAL},
    Result,
};

use super::InterruptController;
use crate::{
    dtb::irqchip::{InterruptHandler, IrqCell, IrqConnection, IrqDesc},
    sync::CleanLockToken,
};

pub struct Null;

impl InterruptHandler for Null {
    unsafe fn irq_handler(&self, _irq: u32, _token: &mut CleanLockToken) {}
}

impl InterruptController for Null {
    unsafe fn irq_init(
        &mut self,
        _fdt_opt: Option<&Fdt>,
        _irq_desc: &mut [IrqDesc; 1024],
        _ic_idx: usize,
        _irq_idx: &mut usize,
        _phandle: u32,
        _parents: &[IrqConnection],
    ) -> Result<()> {
        Ok(())
    }
    unsafe fn irq_ack(&self) -> u32 {
        unimplemented!()
    }
    unsafe fn irq_eoi(&self, _irq_num: u32) {}
    unsafe fn irq_enable(&self, _irq_num: u32) {}
    unsafe fn irq_disable(&self, _irq_num: u32) {}
    fn irq_xlate(&self, _irq_data: IrqCell) -> Result<usize> {
        Err(Error::new(EINVAL))
    }
    fn irq_to_virq(&self, _hwirq: u32) -> Option<usize> {
        None
    }
}
