use core::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use context;
use context::timeout;
use device::pic;
use device::serial::{COM1, COM2};
use ipi::{ipi, IpiKind, IpiTarget};
use time;

//resets to 0 in context::switch()
pub static PIT_TICKS: AtomicUsize = ATOMIC_USIZE_INIT;

unsafe fn trigger(irq: u8) {
    extern {
        fn irq_trigger(irq: u8);
    }

    if irq < 16 {
        if irq >= 8 {
            pic::SLAVE.mask_set(irq - 8);
            pic::MASTER.ack();
            pic::SLAVE.ack();
        } else {
            pic::MASTER.mask_set(irq);
            pic::MASTER.ack();
        }
    }

    irq_trigger(irq);
}

pub unsafe fn acknowledge(irq: usize) {
    if irq < 16 {
        if irq >= 8 {
            pic::SLAVE.mask_clear(irq as u8 - 8);
        } else {
            pic::MASTER.mask_clear(irq as u8);
        }
    }
}

interrupt!(pit, {
    // Saves CPU time by not sending IRQ event irq_trigger(0);

    const PIT_RATE: u64 = 2_250_286;

    {
        let mut offset = time::OFFSET.lock();
        let sum = offset.1 + PIT_RATE;
        offset.1 = sum % 1_000_000_000;
        offset.0 += sum / 1_000_000_000;
    }

    pic::MASTER.ack();

    // Wake up other CPUs
    ipi(IpiKind::Pit, IpiTarget::Other);

    // Any better way of doing this?
    timeout::trigger();

    if PIT_TICKS.fetch_add(1, Ordering::SeqCst) >= 10 {
        let _ = context::switch();
    }
});

interrupt!(keyboard, {
    trigger(1);
});

interrupt!(cascade, {
    // No need to do any operations on cascade
    pic::MASTER.ack();
});

interrupt!(com2, {
    COM2.lock().receive();
    pic::MASTER.ack();
});

interrupt!(com1, {
    COM1.lock().receive();
    pic::MASTER.ack();
});

interrupt!(lpt2, {
    trigger(5);
});

interrupt!(floppy, {
    trigger(6);
});

interrupt!(lpt1, {
    trigger(7);
});

interrupt!(rtc, {
    trigger(8);
});

interrupt!(pci1, {
    trigger(9);
});

interrupt!(pci2, {
    trigger(10);
});

interrupt!(pci3, {
    trigger(11);
});

interrupt!(mouse, {
    trigger(12);
});

interrupt!(fpu, {
    trigger(13);
});

interrupt!(ata1, {
    trigger(14);
});

interrupt!(ata2, {
    trigger(15);
});
