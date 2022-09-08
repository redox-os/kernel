use core::sync::atomic::Ordering;
use x86::tlb;

use crate::context;
use crate::device::local_apic::LOCAL_APIC;
use super::irq::PIT_TICKS;

interrupt!(wakeup, || {
    LOCAL_APIC.eoi();
});

interrupt!(tlb, || {
    LOCAL_APIC.eoi();

    tlb::flush_all();
});

interrupt!(switch, || {
    LOCAL_APIC.eoi();

    let _ = context::switch();
});

interrupt!(pit, || {
    LOCAL_APIC.eoi();

    // Switch after 3 ticks (about 6.75 ms)
    if PIT_TICKS.fetch_add(1, Ordering::SeqCst) >= 2 {
        let _ = context::switch();
    }
});
