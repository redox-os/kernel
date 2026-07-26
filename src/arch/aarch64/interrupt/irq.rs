use crate::{
    arch::{
        device::{generic_timer, irqchip},
        ipi,
    },
    dtb::irqchip::IRQ_CHIP,
    sync::CleanLockToken,
};

// use crate::percpu::PercpuBlock;

unsafe fn dispatch() {
    let (raw_iar, hwirq, virq) = irqchip::acknowledge_root();
    if ipi::handle(hwirq, raw_iar) {
        return;
    }

    let mut token = unsafe { CleanLockToken::new() };
    if generic_timer::handle(hwirq, raw_iar, &mut token) {
        return;
    }

    if let Some(virq) = virq
        && virq < 1024
    {
        unsafe { IRQ_CHIP.trigger_virq(virq as u32, &mut token) };
    } else {
        println!("unexpected irq num {}", hwirq);
        // IDs 1020..1023 are special/spurious GIC values and must not be
        // written to EOIR because no interrupt was acknowledged.
        if hwirq < 1020 {
            irqchip::end_root(raw_iar);
        }
    }
}

exception_stack!(irq_at_el0, |_stack| { unsafe { dispatch() } });

exception_stack!(irq_at_el1, |_stack| { unsafe { dispatch() } });

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
