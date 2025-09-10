use crate::{context, device::local_apic::the_local_apic, percpu::PercpuBlock};

interrupt!(wakeup, || {
    unsafe { the_local_apic().eoi() };
});

interrupt!(tlb, || {
    PercpuBlock::current().maybe_handle_tlb_shootdown();

    unsafe { the_local_apic().eoi() };
});

interrupt!(switch, || {
    unsafe { the_local_apic().eoi() };

    let _ = context::switch();
});

interrupt!(pit, || {
    unsafe { the_local_apic().eoi() };

    // Switch after a sufficient amount of time since the last switch.
    context::switch::tick();
});
