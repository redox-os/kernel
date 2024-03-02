use core::sync::atomic::Ordering;

use x86::tlb;

use crate::percpu::PercpuBlock;
use crate::{context, device::local_apic::LOCAL_APIC};

interrupt!(wakeup, || {
    LOCAL_APIC.eoi();
});

interrupt!(tlb, || {
    tlb_shootdown_handler();

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

unsafe fn tlb_shootdown_handler() {
    let pcpu = PercpuBlock::current();

    if pcpu.wants_tlb_shootdown.swap(false, Ordering::Relaxed) == false {
        // Spurious TLB IPI, could have been manually triggered after the IPI was sent.
        return;
    }

    tlb::flush_all();

    {
        let addrsp = pcpu.current_addrsp.borrow();
        if let Some(ref addrsp) = &*addrsp {
            addrsp.tlb_ack.fetch_add(1, Ordering::Release);
        }
    }
}
