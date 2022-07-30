use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::vec::Vec;

use crate::{interrupt, interrupt_stack};
use crate::context::timeout;
use crate::device::{local_apic, ioapic, pic};
use crate::device::serial::{COM1, COM2};
use crate::ipi::{ipi, IpiKind, IpiTarget};
use crate::scheme::debug::{debug_input, debug_notify};
use crate::{context, time};

//resets to 0 in context::switch()
#[thread_local]
pub static PIT_TICKS: AtomicUsize = AtomicUsize::new(0);

// The only way to read PS2 data without race conditions is to allow a keyboard interrupt to happen
// and then read data while reading mouse data, since keyboard data overrides mouse data and
// reading the status register is not done atomically with reading the data. This is not possible
// from userspace, so we do this minimal part of the PS2 driver in the kernel.
#[inline(always)]
unsafe fn ps2_interrupt(_index: usize) {
    use crate::scheme::serio::serio_input;

    let data: u8;
    let status: u8;
    core::arch::asm!("
        sti
        nop
        cli
        in al, 0x64
        mov ah, al
        in al, 0x60
        mov {}, al
        mov {}, ah
        ",
         out(reg_byte) data,
         out(reg_byte) status,
    );

    if status & 1 != 0 {
        let status_index = if status & (1 << 5) == 0 {
            // Keyboard, according to status
            0
        } else {
            // Mouse, according to status
            1
        };
        serio_input(status_index, data);
    }
}

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
        IrqMethod::Pic => {
            Ok(format!("{}\tIRQ7\n{}\tIRQ15\n{}\ttotal\n", spurious_count_irq7(), spurious_count_irq15(), spurious_count()).into_bytes())
        }
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

extern {
    // triggers irq scheme
    fn irq_trigger(irq: u8);
}

/// Notify the IRQ scheme that an IRQ has been registered. This should mask the IRQ until the
/// scheme user unmasks it ("acknowledges" it).
unsafe fn trigger(irq: u8) {
    match irq_method() {
        IrqMethod::Pic => if irq < 16 { pic_mask(irq) },
        IrqMethod::Apic => ioapic_mask(irq),
    }
    irq_trigger(irq);
}

/// Unmask the IRQ. This is called from the IRQ scheme, which does this when a user process has
/// processed the IRQ.
pub unsafe fn acknowledge(irq: usize) {
    match irq_method() {
        IrqMethod::Pic => if irq < 16 { pic_unmask(irq) },
        IrqMethod::Apic => ioapic_unmask(irq),
    }
}

/// Sends an end-of-interrupt, so that the interrupt controller can go on to the next one.
pub unsafe fn eoi(irq: u8) {
    match irq_method() {
        IrqMethod::Pic => if irq < 16 { pic_eoi(irq) },
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
    local_apic::LOCAL_APIC.eoi()
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

    const PIT_RATE: u64 = 2_250_286;

    {
        let mut offset = time::OFFSET.lock();
        let sum = offset.1 + PIT_RATE;
        offset.1 = sum % 1_000_000_000;
        offset.0 += sum / 1_000_000_000;
    }

    eoi(0);

    // Wake up other CPUs
    ipi(IpiKind::Pit, IpiTarget::Other);

    // Any better way of doing this?
    timeout::trigger();

    if PIT_TICKS.fetch_add(1, Ordering::SeqCst) >= 10 {
        let _ = context::switch();
    }
});

interrupt!(keyboard, || {
    ps2_interrupt(0);
    eoi(1);
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
    ps2_interrupt(1);
    eoi(12);
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
        return
    }
    trigger(15);
    eoi(15);
});

interrupt!(lapic_timer, || {
    println!("Local apic timer interrupt");
    lapic_eoi();
});

interrupt!(lapic_error, || {
    println!("Local apic internal error: ESR={:#0x}", local_apic::LOCAL_APIC.esr());
    lapic_eoi();
});

interrupt!(calib_pit, || {
    const PIT_RATE: u64 = 2_250_286;

    {
        let mut offset = time::OFFSET.lock();
        let sum = offset.1 + PIT_RATE;
        offset.1 = sum % 1_000_000_000;
        offset.0 += sum / 1_000_000_000;
    }

    eoi(0);
});
// XXX: This would look way prettier using const generics.

macro_rules! allocatable_irq(
    ( $idt:expr, $number:literal, $name:ident ) => {
        interrupt!($name, || {
            allocatable_irq_generic($number);
        });
    }
);

pub unsafe fn allocatable_irq_generic(number: u8) {
    irq_trigger(number - 32);
    lapic_eoi();
}

define_default_irqs!();
