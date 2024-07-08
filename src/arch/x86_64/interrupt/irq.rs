use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::vec::Vec;

use crate::{
    context,
    context::timeout,
    device::{
        ioapic, local_apic, pic, pit,
        serial::{COM1, COM2},
    },
    interrupt, interrupt_stack,
    ipi::{ipi, IpiKind, IpiTarget},
    scheme::{
        debug::{debug_input, debug_notify},
        serio::serio_input,
    },
    time,
};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqMethod {
    Pic = 0,
    Apic = 1,
}

static SPURIOUS_COUNT_IRQ7: AtomicUsize = AtomicUsize::new(0);
static SPURIOUS_COUNT_IRQ15: AtomicUsize = AtomicUsize::new(0);

pub fn spurious_count_irq7() -> usize {
    SPURIOUS_COUNT_IRQ7.load(Ordering::Relaxed)
}
pub fn spurious_count_irq15() -> usize {
    SPURIOUS_COUNT_IRQ15.load(Ordering::Relaxed)
}
pub fn spurious_count() -> usize {
    spurious_count_irq7() + spurious_count_irq15()
}
pub fn spurious_irq_resource() -> syscall::Result<Vec<u8>> {
    match irq_method() {
        IrqMethod::Apic => Ok(Vec::from(&b"(not implemented for APIC yet)"[..])),
        IrqMethod::Pic => Ok(format!(
            "{}\tIRQ7\n{}\tIRQ15\n{}\ttotal\n",
            spurious_count_irq7(),
            spurious_count_irq15(),
            spurious_count()
        )
        .into_bytes()),
    }
}

static IRQ_METHOD: AtomicUsize = AtomicUsize::new(IrqMethod::Pic as usize);

pub fn set_irq_method(method: IrqMethod) {
    IRQ_METHOD.store(method as usize, core::sync::atomic::Ordering::Release);
}

fn irq_method() -> IrqMethod {
    let raw = IRQ_METHOD.load(core::sync::atomic::Ordering::Acquire);

    match raw {
        0 => IrqMethod::Pic,
        1 => IrqMethod::Apic,
        _ => unreachable!(),
    }
}

extern "C" {
    // triggers irq scheme
    fn irq_trigger(irq: u8);
}

/// Notify the IRQ scheme that an IRQ has been registered. This should mask the IRQ until the
/// scheme user unmasks it ("acknowledges" it).
unsafe fn trigger(irq: u8) {
    match irq_method() {
        IrqMethod::Pic => {
            if irq < 16 {
                pic_mask(irq)
            }
        }
        IrqMethod::Apic => ioapic_mask(irq),
    }
    irq_trigger(irq);
}

/// Unmask the IRQ. This is called from the IRQ scheme, which does this when a user process has
/// processed the IRQ.
pub unsafe fn acknowledge(irq: usize) {
    match irq_method() {
        IrqMethod::Pic => {
            if irq < 16 {
                pic_unmask(irq)
            }
        }
        IrqMethod::Apic => ioapic_unmask(irq),
    }
}

/// Sends an end-of-interrupt, so that the interrupt controller can go on to the next one.
pub unsafe fn eoi(irq: u8) {
    match irq_method() {
        IrqMethod::Pic => {
            if irq < 16 {
                pic_eoi(irq)
            }
        }
        IrqMethod::Apic => lapic_eoi(),
    }
}

unsafe fn pic_mask(irq: u8) {
    debug_assert!(irq < 16);

    if irq >= 8 {
        pic::SLAVE.mask_set(irq - 8);
    } else {
        pic::MASTER.mask_set(irq);
    }
}

unsafe fn ioapic_mask(irq: u8) {
    ioapic::mask(irq);
}

unsafe fn pic_eoi(irq: u8) {
    debug_assert!(irq < 16);

    if irq >= 8 {
        pic::MASTER.ack();
        pic::SLAVE.ack();
    } else {
        pic::MASTER.ack();
    }
}

unsafe fn lapic_eoi() {
    local_apic::the_local_apic().eoi()
}

unsafe fn pic_unmask(irq: usize) {
    debug_assert!(irq < 16);

    if irq >= 8 {
        pic::SLAVE.mask_clear(irq as u8 - 8);
    } else {
        pic::MASTER.mask_clear(irq as u8);
    }
}

unsafe fn ioapic_unmask(irq: usize) {
    ioapic::unmask(irq as u8);
}

interrupt_stack!(pit_stack, |_stack| {
    // Saves CPU time by not sending IRQ event irq_trigger(0);

    {
        *time::OFFSET.lock() += pit::RATE;
    }

    eoi(0);

    // Wake up other CPUs
    ipi(IpiKind::Pit, IpiTarget::Other);

    // Any better way of doing this?
    timeout::trigger();

    // Switch after a sufficient amount of time since the last switch.
    context::switch::tick();
});

interrupt!(keyboard, || {
    let data: u8;
    core::arch::asm!("in al, 0x60", out("al") data);

    eoi(1);

    serio_input(0, data);
});

interrupt!(cascade, || {
    // No need to do any operations on cascade
    eoi(2);
});

interrupt!(com2, || {
    while let Some(c) = COM2.lock().receive() {
        debug_input(c);
    }
    debug_notify();
    eoi(3);
});

interrupt!(com1, || {
    while let Some(c) = COM1.lock().receive() {
        debug_input(c);
    }
    debug_notify();
    eoi(4);
});

interrupt!(lpt2, || {
    trigger(5);
    eoi(5);
});

interrupt!(floppy, || {
    trigger(6);
    eoi(6);
});

interrupt!(lpt1, || {
    if irq_method() == IrqMethod::Pic && pic::MASTER.isr() & (1 << 7) == 0 {
        // the IRQ was spurious, ignore it but increment a counter.
        SPURIOUS_COUNT_IRQ7.fetch_add(1, Ordering::Relaxed);
        return;
    }
    trigger(7);
    eoi(7);
});

interrupt!(rtc, || {
    trigger(8);
    eoi(8);
});

interrupt!(pci1, || {
    trigger(9);
    eoi(9);
});

interrupt!(pci2, || {
    trigger(10);
    eoi(10);
});

interrupt!(pci3, || {
    trigger(11);
    eoi(11);
});

interrupt!(mouse, || {
    let data: u8;
    core::arch::asm!("in al, 0x60", out("al") data);

    eoi(12);

    serio_input(1, data);
});

interrupt!(fpu, || {
    trigger(13);
    eoi(13);
});

interrupt!(ata1, || {
    trigger(14);
    eoi(14);
});

interrupt!(ata2, || {
    if irq_method() == IrqMethod::Pic && pic::SLAVE.isr() & (1 << 7) == 0 {
        SPURIOUS_COUNT_IRQ15.fetch_add(1, Ordering::Relaxed);
        pic::MASTER.ack();
        return;
    }
    trigger(15);
    eoi(15);
});

interrupt!(lapic_timer, || {
    println!("Local apic timer interrupt");
    lapic_eoi();
});
#[cfg(feature = "profiling")]
interrupt!(aux_timer, || {
    lapic_eoi();
    crate::ipi::ipi(IpiKind::Profile, IpiTarget::Other);
});

interrupt!(lapic_error, || {
    log::error!(
        "Local apic internal error: ESR={:#0x}",
        local_apic::the_local_apic().esr()
    );
    lapic_eoi();
});

interrupt_error!(generic_irq, |_stack, code| {
    // The reason why 128 is subtracted and added from the code, is that PUSH imm8 sign-extends the
    // value, and the longer PUSH imm32 would make the generic_interrupts table twice as large
    // (containing lots of useless NOPs).
    irq_trigger((code as i32).wrapping_add(128) as u8);

    lapic_eoi();
});

core::arch::global_asm!("
    .globl __generic_interrupts_start
    .globl __generic_interrupts_end
    .p2align 3
__generic_interrupts_start:
    n = 0
    .rept 224
    push (n - 128)
    jmp {}
    .p2align 3
    n = n + 1
    .endr
__generic_interrupts_end:
", sym generic_irq);

extern "C" {
    pub fn __generic_interrupts_start();
    pub fn __generic_interrupts_end();
}
