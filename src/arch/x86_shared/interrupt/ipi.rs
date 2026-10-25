use crate::{
    arch::device::local_apic::{self, the_local_apic},
    context::{self, switch::drain_ipi_context_wakeups},
    percpu::PercpuBlock,
    sync::CleanLockToken,
};

interrupt!(wakeup, || {
    let mut token = unsafe { CleanLockToken::new() };
    drain_ipi_context_wakeups(&mut token);
    unsafe { the_local_apic().eoi() };
});

interrupt!(tlb, || {
    PercpuBlock::current().maybe_handle_tlb_shootdown();

    unsafe { the_local_apic().eoi() };
});

interrupt!(switch, || {
    unsafe { the_local_apic().eoi() };

    let mut token = unsafe { CleanLockToken::new() };
    let _ = context::switch(&mut token);
});

interrupt!(pit, || {
    unsafe { the_local_apic().eoi() };

    // With local APIC ticks this IPI is only sent for APs that could not arm their own
    // timer, but it is broadcast, so a CPU that already ticks itself ignores it.
    if local_apic::has_tsc_deadline_tick() {
        return;
    }

    // Switch after a sufficient amount of time since the last switch.
    let mut token = unsafe { CleanLockToken::new() };
    context::switch::tick(&mut token);
});
