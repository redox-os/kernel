use crate::{context, device::local_apic::the_local_apic, percpu::PercpuBlock};

interrupt!(wakeup, || {
    the_local_apic().eoi();
});

interrupt!(tlb, || {
    PercpuBlock::current().maybe_handle_tlb_shootdown();

    the_local_apic().eoi();
});

interrupt!(switch, || {
    the_local_apic().eoi();

    let _ = context::switch();
});

interrupt!(pit, || {
    the_local_apic().eoi();

    // Switch after a sufficient amount of time since the last switch.
    context::switch::tick();
});
