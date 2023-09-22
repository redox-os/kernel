use core::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use crate::context;
use crate::context::timeout;
use crate::device::generic_timer::{GENTIMER};
use crate::device::irqchip::IRQ_CHIP;
use crate::device::serial::{COM1};
use crate::time;

use crate::{exception_stack};

exception_stack!(irq_at_el0, |stack| {
    match IRQ_CHIP.irq_ack() {
        30 => irq_handler_gentimer(30),
        33 => irq_handler_com1(33),
        _ => panic!("irq_demux: unregistered IRQ"),
    }
});

exception_stack!(irq_at_el1, |stack| {
    match IRQ_CHIP.irq_ack() {
        30 => irq_handler_gentimer(30),
        33 => irq_handler_com1(33),
        _ => panic!("irq_demux: unregistered IRQ"),
    }
});

unsafe fn trigger(irq: u32) {
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

unsafe fn irq_demux() {
    match IRQ_CHIP.irq_ack() {
        30 => irq_handler_gentimer(30),
        33 => irq_handler_com1(33),
        _ => panic!("irq_demux: unregistered IRQ"),
    }
}
