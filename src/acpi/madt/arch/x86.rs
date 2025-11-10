use core::{
    hint,
    sync::atomic::{AtomicU8, Ordering},
};

use crate::{
    arch::start::KernelArgsAp,
    cpu_set::LogicalCpuId,
    device::local_apic::the_local_apic,
    memory::{allocate_p2frame, Frame, KernelMapper},
    paging::{Page, PageFlags, PhysicalAddress, RmmA, RmmArch, VirtualAddress, PAGE_SIZE},
    start::{kstart_ap, AP_READY},
};

use super::{Madt, MadtEntry};

const TRAMPOLINE: usize = 0x8000;
static TRAMPOLINE_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trampoline"));

pub(super) fn init(madt: Madt) {
    let local_apic = unsafe { the_local_apic() };
    let me = local_apic.id();

    if local_apic.x2 {
        debug!("    X2APIC {}", me.get());
    } else {
        debug!("    XAPIC {}: {:>08X}", me.get(), local_apic.address);
    }

    if cfg!(not(feature = "multi_core")) {
        return;
    }

    // Map trampoline
    let trampoline_frame = Frame::containing(PhysicalAddress::new(TRAMPOLINE));
    let trampoline_page = Page::containing_address(VirtualAddress::new(TRAMPOLINE));
    let (result, page_table_physaddr) = unsafe {
        //TODO: do not have writable and executable!
        let mut mapper = KernelMapper::lock();

        let result = mapper
            .get_mut()
            .expect(
                "expected kernel page table not to be recursively locked while initializing MADT",
            )
            .map_phys(
                trampoline_page.start_address(),
                trampoline_frame.base(),
                PageFlags::new().execute(true).write(true),
            )
            .expect("failed to map trampoline");

        (result, mapper.table().phys().data())
    };
    result.flush();

    // Write trampoline, make sure TRAMPOLINE page is free for use
    for (i, val) in TRAMPOLINE_DATA.iter().enumerate() {
        unsafe {
            (*((TRAMPOLINE as *mut u8).add(i) as *const AtomicU8)).store(*val, Ordering::SeqCst);
        }
    }

    for madt_entry in madt.iter() {
        debug!("      {:x?}", madt_entry);
        if let MadtEntry::LocalApic(ap_local_apic) = madt_entry {
            if u32::from(ap_local_apic.id) == me.get() {
                debug!("        This is my local APIC");
            } else if ap_local_apic.flags & 1 == 1 {
                let cpu_id = LogicalCpuId::next();

                // Allocate a stack
                let stack_start = allocate_p2frame(4)
                    .expect("no more frames in acpi stack_start")
                    .base()
                    .data()
                    + crate::PHYS_OFFSET;
                let stack_end = stack_start + (PAGE_SIZE << 4);

                let pcr_ptr = crate::arch::gdt::allocate_and_init_pcr(cpu_id, stack_end);

                let idt_ptr = crate::arch::idt::allocate_and_init_idt(cpu_id);

                let args = KernelArgsAp {
                    stack_end: stack_end as *mut u8,
                    cpu_id,
                    pcr_ptr,
                    idt_ptr,
                };

                let ap_ready = (TRAMPOLINE + 8) as *mut u64;
                let ap_args_ptr = unsafe { ap_ready.add(1) };
                let ap_page_table = unsafe { ap_ready.add(2) };
                let ap_code = unsafe { ap_ready.add(3) };

                // Set the ap_ready to 0, volatile
                unsafe {
                    ap_ready.write(0);
                    ap_args_ptr.write(&args as *const _ as u64);
                    ap_page_table.write(page_table_physaddr as u64);
                    ap_code.write(kstart_ap as u64);

                    // TODO: Is this necessary (this fence)?
                    core::arch::asm!("");
                };
                AP_READY.store(false, Ordering::SeqCst);

                // Send INIT IPI
                {
                    let mut icr = 0x4500;
                    if local_apic.x2 {
                        icr |= u64::from(ap_local_apic.id) << 32;
                    } else {
                        icr |= u64::from(ap_local_apic.id) << 56;
                    }
                    local_apic.set_icr(icr);
                }

                // Send START IPI
                {
                    let ap_segment = (TRAMPOLINE >> 12) & 0xFF;
                    let mut icr = 0x4600 | ap_segment as u64;

                    if local_apic.x2 {
                        icr |= u64::from(ap_local_apic.id) << 32;
                    } else {
                        icr |= u64::from(ap_local_apic.id) << 56;
                    }

                    local_apic.set_icr(icr);
                }

                // Wait for trampoline ready
                while unsafe { (*ap_ready.cast::<AtomicU8>()).load(Ordering::SeqCst) } == 0 {
                    hint::spin_loop();
                }
                while !AP_READY.load(Ordering::SeqCst) {
                    hint::spin_loop();
                }

                unsafe {
                    RmmA::invalidate_all();
                }
            }
        }
    }

    // Unmap trampoline
    let (_frame, _, flush) = unsafe {
        KernelMapper::lock()
            .get_mut()
            .expect(
                "expected kernel page table not to be recursively locked while initializing MADT",
            )
            .unmap_phys(trampoline_page.start_address(), true)
            .expect("failed to unmap trampoline page")
    };
    flush.flush();
}
