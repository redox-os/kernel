use core::sync::atomic::Ordering;

use x86::tlb;

use crate::percpu::PercpuBlock;
use crate::{context, device::local_apic::LOCAL_APIC};

interrupt!(wakeup, || {
    LOCAL_APIC.eoi();
});

interrupt!(tlb, || {
    PercpuBlock::current().maybe_handle_tlb_shootdown();

    LOCAL_APIC.eoi();
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
