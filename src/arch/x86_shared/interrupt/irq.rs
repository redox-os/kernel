use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::vec::Vec;

use crate::{
    context::{self, timeout},
    device::{
        ioapic, local_apic, pic, pit,
        serial::{COM1, COM2},
    },
    ipi::{ipi, IpiKind, IpiTarget},
    percpu::PercpuBlock,
    scheme::{irq::irq_trigger, serio::serio_input},
    sync::CleanLockToken,
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
pub fn spurious_irq_resource(_token: &mut CleanLockToken) -> syscall::Result<Vec<u8>> {
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

/// Notify the IRQ scheme that an IRQ has been registered. This should mask the IRQ until the
/// scheme user unmasks it ("acknowledges" it).
unsafe fn trigger(irq: u8) {
    unsafe {
        match irq_method() {
            IrqMethod::Pic => {
                if irq < 16 {
                    pic_mask(irq)
                }
            }
            IrqMethod::Apic => ioapic_mask(irq),
        }
        let mut token = CleanLockToken::new();
        irq_trigger(irq, &mut token);
    }
}

/// Unmask the IRQ. This is called from the IRQ scheme, which does this when a user process has
/// processed the IRQ.
pub unsafe fn acknowledge(irq: usize) {
    unsafe {
        match irq_method() {
            IrqMethod::Pic => {
                if irq < 16 {
                    pic_unmask(irq)
                }
            }
            IrqMethod::Apic => ioapic_unmask(irq),
        }
    }
}

/// Sends an end-of-interrupt, so that the interrupt controller can go on to the next one.
pub unsafe fn eoi(irq: u8) {
    unsafe {
        PercpuBlock::current().stats.add_irq(irq);

        match irq_method() {
            IrqMethod::Pic => {
                if irq < 16 {
                    pic_eoi(irq)
                }
            }
            IrqMethod::Apic => lapic_eoi(),
        }
    }
}

unsafe fn pic_mask(irq: u8) {
    unsafe {
        debug_assert!(irq < 16);

        if irq >= 8 {
            pic::slave().mask_set(irq - 8);
        } else {
            pic::master().mask_set(irq);
        }
    }
}

unsafe fn ioapic_mask(irq: u8) {
    unsafe {
        ioapic::mask(irq);
    }
}

unsafe fn pic_eoi(irq: u8) {
    unsafe {
        debug_assert!(irq < 16);

        if irq >= 8 {
            pic::master().ack();
            pic::slave().ack();
        } else {
            pic::master().ack();
        }
    }
}

unsafe fn lapic_eoi() {
    unsafe { local_apic::the_local_apic().eoi() }
}

unsafe fn pic_unmask(irq: usize) {
    unsafe {
        debug_assert!(irq < 16);

        if irq >= 8 {
            pic::slave().mask_clear(irq as u8 - 8);
        } else {
            pic::master().mask_clear(irq as u8);
        }
    }
}

unsafe fn ioapic_unmask(irq: usize) {
    unsafe {
        ioapic::unmask(irq as u8);
    }
}

interrupt_stack!(pit_stack, |_stack| {
    // Saves CPU time by not sending IRQ event irq_trigger(0);

    {
        *time::OFFSET.lock() += pit::RATE;
    }

    unsafe { eoi(0) };

    // Wake up other CPUs
    ipi(IpiKind::Pit, IpiTarget::Other);

    let mut token = unsafe { CleanLockToken::new() };

    // Any better way of doing this?
    timeout::trigger(&mut token);

    // Switch after a sufficient amount of time since the last switch.
    context::switch::tick(&mut token);
});

interrupt!(keyboard, || {
    let data: u8;
    unsafe { core::arch::asm!("in al, 0x60", out("al") data) };

    unsafe { eoi(1) };

    let mut token = unsafe { CleanLockToken::new() };
    serio_input(0, data, &mut token);
});

interrupt!(cascade, || {
    // No need to do any operations on cascade
    unsafe { eoi(2) };
});

interrupt!(com2, || {
    let mut token = unsafe { CleanLockToken::new() };
    COM2.lock().receive(&mut token);
    unsafe { eoi(3) };
});

interrupt!(com1, || {
    let mut token = unsafe { CleanLockToken::new() };
    COM1.lock().receive(&mut token);
    unsafe { eoi(4) };
});

interrupt!(lpt2, || {
    unsafe {
        trigger(5);
        eoi(5);
    }
});

interrupt!(floppy, || {
    unsafe {
        trigger(6);
        eoi(6);
    }
});

interrupt!(lpt1, || {
    unsafe {
        if irq_method() == IrqMethod::Pic && pic::master().isr() & (1 << 7) == 0 {
            // the IRQ was spurious, ignore it but increment a counter.
            SPURIOUS_COUNT_IRQ7.fetch_add(1, Ordering::Relaxed);
            return;
        }
        trigger(7);
        eoi(7);
    }
});

interrupt!(rtc, || {
    unsafe {
        trigger(8);
        eoi(8);
    }
});

interrupt!(pci1, || {
    unsafe {
        trigger(9);
        eoi(9);
    }
});

interrupt!(pci2, || {
    unsafe {
        trigger(10);
        eoi(10);
    }
});

interrupt!(pci3, || {
    unsafe {
        trigger(11);
        eoi(11);
    }
});

interrupt!(mouse, || {
    let data: u8;
    unsafe { core::arch::asm!("in al, 0x60", out("al") data) };

    unsafe { eoi(12) };

    let mut token = unsafe { CleanLockToken::new() };
    serio_input(1, data, &mut token);
});

interrupt!(fpu, || {
    unsafe {
        trigger(13);
        eoi(13);
    }
});

interrupt!(ata1, || {
    unsafe {
        trigger(14);
        eoi(14);
    }
});

interrupt!(ata2, || {
    unsafe {
        if irq_method() == IrqMethod::Pic && pic::slave().isr() & (1 << 7) == 0 {
            SPURIOUS_COUNT_IRQ15.fetch_add(1, Ordering::Relaxed);
            pic::master().ack();
            return;
        }
        trigger(15);
        eoi(15);
    }
});

interrupt!(lapic_timer, || {
    println!("Local apic timer interrupt");
    unsafe { lapic_eoi() };
});
#[cfg(feature = "profiling")]
interrupt!(aux_timer, || {
    unsafe { lapic_eoi() };
    crate::ipi::ipi(IpiKind::Profile, IpiTarget::Other);
});

interrupt!(lapic_error, || {
    error!("Local apic internal error: ESR={:#0x}", unsafe {
        local_apic::the_local_apic().esr()
    });
    unsafe { lapic_eoi() };
});

interrupt_error!(generic_irq, |_stack, code| {
    let mut token = unsafe { CleanLockToken::new() };

    // The reason why 128 is subtracted and added from the code, is that PUSH imm8 sign-extends the
    // value, and the longer PUSH imm32 would make the generic_interrupts table twice as large
    // (containing lots of useless NOPs).
    irq_trigger((code as i32).wrapping_add(128) as u8, &mut token);

    unsafe { lapic_eoi() };
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

unsafe extern "C" {
    pub fn __generic_interrupts_start();
    pub fn __generic_interrupts_end();
}
