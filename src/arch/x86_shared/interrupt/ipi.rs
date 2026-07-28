use crate::{
    arch::device::local_apic::the_local_apic,
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

    // Switch after a sufficient amount of time since the last switch.
    let mut token = unsafe { CleanLockToken::new() };
    context::switch::tick(&mut token);
});
