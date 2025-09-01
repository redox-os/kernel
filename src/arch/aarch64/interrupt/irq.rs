use crate::{arch::device::ROOT_IC_IDX, dtb::irqchip::IRQ_CHIP, scheme::irq::irq_trigger};
use core::sync::atomic::Ordering;

#[cfg(feature = "sys_stat")]
use crate::percpu::PercpuBlock;

unsafe fn irq_ack() -> (u32, Option<usize>) {
    let ic = &mut IRQ_CHIP.irq_chip_list.chips[ROOT_IC_IDX.load(Ordering::Relaxed)].ic;
    let irq = ic.irq_ack();
    (irq, ic.irq_to_virq(irq))
}

exception_stack!(irq_at_el0, |_stack| {
    let (irq, virq) = irq_ack();
    if let Some(virq) = virq
        && virq < 1024
    {
        IRQ_CHIP.trigger_virq(virq as u32);
    } else {
        println!("unexpected irq num {}", irq);
    }
});

exception_stack!(irq_at_el1, |_stack| {
    let (irq, virq) = irq_ack();
    if let Some(virq) = virq
        && virq < 1024
    {
        IRQ_CHIP.trigger_virq(virq as u32);
    } else {
        println!("unexpected irq num {}", irq);
    }
});

//TODO
pub unsafe fn trigger(irq: u32) {
    #[cfg(feature = "sys_stat")]
    PercpuBlock::current().stats.add_irq(irq);

    irq_trigger(irq.try_into().unwrap());
    IRQ_CHIP.irq_eoi(irq);
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
