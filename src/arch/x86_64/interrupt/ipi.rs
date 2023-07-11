use x86::tlb;

use crate::context;
use crate::device::local_apic::LOCAL_APIC;

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

    // Switch after a sufficient amount of time since the last switch.
    context::switch::tick();
});
