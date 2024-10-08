use crate::device::irqchip::IRQ_CHIP;

exception_stack!(irq_at_el0, |_stack| {
    let irq = IRQ_CHIP.irq_ack();
    if let Some(virq) = IRQ_CHIP.irq_to_virq(irq)
        && virq < 1024
    {
        if let Some(handler) = &mut IRQ_CHIP.irq_desc[virq].handler {
            handler.irq_handler(virq as u32);
        } else if let Some(ic_idx) = IRQ_CHIP.irq_desc[virq].basic.child_ic_idx {
            IRQ_CHIP.irq_chip_list.chips[ic_idx]
                .ic
                .irq_handler(virq as u32);
        }
    } else {
        println!("unexpected irq num {}", irq);
    }
});

exception_stack!(irq_at_el1, |_stack| {
    let irq = IRQ_CHIP.irq_ack();
    if let Some(virq) = IRQ_CHIP.irq_to_virq(irq)
        && virq < 1024
    {
        if let Some(handler) = &mut IRQ_CHIP.irq_desc[virq].handler {
            handler.irq_handler(virq as u32);
        } else if let Some(ic_idx) = IRQ_CHIP.irq_desc[virq].basic.child_ic_idx {
            IRQ_CHIP.irq_chip_list.chips[ic_idx]
                .ic
                .irq_handler(virq as u32);
        }
    } else {
        println!("unexpected irq num {}", irq);
    }
});

//TODO
pub unsafe fn trigger(irq: u32) {
    extern "C" {
        fn irq_trigger(irq: u32);
    }

    irq_trigger(irq);
    IRQ_CHIP.irq_eoi(irq);
}

pub unsafe fn acknowledge(_irq: usize) {
    // TODO
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
