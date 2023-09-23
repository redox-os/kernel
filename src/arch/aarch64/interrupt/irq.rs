use crate::context;
use crate::context::timeout;
//use crate::device::generic_timer::{GENTIMER};
use crate::device::irqchip::IRQ_CHIP;
use crate::device::serial::{COM1};
use crate::time;

use crate::{exception_stack};

exception_stack!(irq_at_el0, |stack| {
    let irq = IRQ_CHIP.irq_ack();
    if irq >= 1024 {
        println!("unexpected irq num {}", irq);
    } else {
        if let Some(handler) = &mut IRQ_CHIP.handlers[irq as usize] {
            handler.irq_handler(irq);
        }
    }
});

exception_stack!(irq_at_el1, |stack| {
    let irq = IRQ_CHIP.irq_ack();
    if irq >= 1024 {
        println!("unexpected irq num {}", irq);
    } else {
        if let Some(handler) = &mut IRQ_CHIP.handlers[irq as usize] {
            handler.irq_handler(irq);
        }
    }
});

pub unsafe fn trigger(irq: u32) {
    extern {
        fn irq_trigger(irq: u32);
    }

    irq_trigger(irq);
    IRQ_CHIP.irq_eoi(irq);
}

pub unsafe fn acknowledge(_irq: usize) {
    // TODO
}

pub unsafe fn irq_handler_com1(irq: u32) {
    if let Some(ref mut serial_port) = *COM1.lock() {
        serial_port.receive();
    };
    trigger(irq);
}

/*
pub unsafe fn irq_handler_gentimer(irq: u32) {
    GENTIMER.clear_irq();
    {
        *time::OFFSET.lock() += GENTIMER.clk_freq as u128;
    }

    timeout::trigger();

    context::switch::tick();

    trigger(irq);
    GENTIMER.reload_count();
}
*/
