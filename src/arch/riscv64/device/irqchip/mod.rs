use crate::dtb::irqchip::InterruptController;
use alloc::boxed::Box;

pub fn new_irqchip(_ic_str: &str) -> Option<Box<dyn InterruptController>> {
    None
}
