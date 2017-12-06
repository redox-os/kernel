use core::sync::atomic::Ordering;

use context;
use device::local_apic::LOCAL_APIC;
use super::irq::PIT_TICKS;

interrupt!(ipi, {
    LOCAL_APIC.eoi();
});

interrupt!(pit, {
    LOCAL_APIC.eoi();

    if PIT_TICKS.fetch_add(1, Ordering::SeqCst) >= 10 {
        let _ = context::switch();
    }
});
