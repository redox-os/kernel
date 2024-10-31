use core::sync::atomic::{AtomicU8, Ordering};

use crate::{
    device::local_apic::the_local_apic,
    interrupt,
    memory::{allocate_p2frame, Frame, KernelMapper},
    paging::{Page, PageFlags, PhysicalAddress, RmmA, RmmArch, VirtualAddress, PAGE_SIZE},
    start::{kstart_ap, AP_READY, CPU_COUNT},
};

use super::{Madt, MadtEntry};

const TRAMPOLINE: usize = 0x8000;
static TRAMPOLINE_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trampoline"));

pub(super) fn init(madt: Madt) {
    let local_apic = unsafe { the_local_apic() };
    let me = local_apic.id() as u8;

    if local_apic.x2 {
        println!("    X2APIC {}", me);
    } else {
        println!("    XAPIC {}: {:>08X}", me, local_apic.address);
    }

    if cfg!(feature = "multi_core") {
        // Map trampoline
        let trampoline_frame = Frame::containing(PhysicalAddress::new(TRAMPOLINE));
        let trampoline_page = Page::containing_address(VirtualAddress::new(TRAMPOLINE));
        let (result, page_table_physaddr) = unsafe {
            //TODO: do not have writable and executable!
            let mut mapper = KernelMapper::lock();

            let result = mapper
                .get_mut()
                .expect("expected kernel page table not to be recursively locked while initializing MADT")
                .map_phys(trampoline_page.start_address(), trampoline_frame.base(), PageFlags::new().execute(true).write(true))
                .expect("failed to map trampoline");

            (result, mapper.table().phys().data())
        };
        result.flush();

        // Write trampoline, make sure TRAMPOLINE page is free for use
        for i in 0..TRAMPOLINE_DATA.len() {
            unsafe {
                (*((TRAMPOLINE as *mut u8).add(i) as *const AtomicU8))
                    .store(TRAMPOLINE_DATA[i], Ordering::SeqCst);
            }
        }

        for madt_entry in madt.iter() {
            println!("      {:#x?}", madt_entry);
            match madt_entry {
                MadtEntry::LocalApic(ap_local_apic) => {
                    if ap_local_apic.id == me {
                        println!("        This is my local APIC");
                    } else {
                        if ap_local_apic.flags & 1 == 1 {
                            // Increase CPU ID
                            CPU_COUNT.fetch_add(1, Ordering::SeqCst);

                            // Allocate a stack
                            let stack_start = allocate_p2frame(4)
                                .expect("no more frames in acpi stack_start")
                                .base()
                                .data()
                                + crate::PHYS_OFFSET;
                            let stack_end = stack_start + (PAGE_SIZE << 4);

                            let ap_ready = (TRAMPOLINE + 8) as *mut u64;
                            let ap_cpu_id = unsafe { ap_ready.add(1) };
                            let ap_page_table = unsafe { ap_ready.add(2) };
                            let ap_stack_start = unsafe { ap_ready.add(3) };
                            let ap_stack_end = unsafe { ap_ready.add(4) };
                            let ap_code = unsafe { ap_ready.add(5) };

                            // Set the ap_ready to 0, volatile
                            unsafe {
                                ap_ready.write(0);
                                ap_cpu_id.write(ap_local_apic.processor.into());
                                ap_page_table.write(page_table_physaddr as u64);
                                ap_stack_start.write(stack_start as u64);
                                ap_stack_end.write(stack_end as u64);
                                ap_code.write(kstart_ap as u64);

                                // TODO: Is this necessary (this fence)?
                                core::arch::asm!("");
                            };
                            AP_READY.store(false, Ordering::SeqCst);

                            print!(
                                "        AP {} APIC {}:",
                                ap_local_apic.processor, ap_local_apic.id
                            );

                            // Send INIT IPI
                            {
                                let mut icr = 0x4500;
                                if local_apic.x2 {
                                    icr |= (ap_local_apic.id as u64) << 32;
                                } else {
                                    icr |= (ap_local_apic.id as u64) << 56;
                                }
                                print!(" IPI...");
                                local_apic.set_icr(icr);
                            }

                            // Send START IPI
                            {
                                //Start at 0x0800:0000 => 0x8000. Hopefully the bootloader code is still there
                                let ap_segment = (TRAMPOLINE >> 12) & 0xFF;
                                let mut icr = 0x4600 | ap_segment as u64;

                                if local_apic.x2 {
                                    icr |= (ap_local_apic.id as u64) << 32;
                                } else {
                                    icr |= (ap_local_apic.id as u64) << 56;
                                }

                                print!(" SIPI...");
                                local_apic.set_icr(icr);
                            }

                            // Wait for trampoline ready
                            print!(" Wait...");
                            while unsafe { (*ap_ready.cast::<AtomicU8>()).load(Ordering::SeqCst) }
                                == 0
                            {
                                interrupt::pause();
                            }
                            print!(" Trampoline...");
                            while !AP_READY.load(Ordering::SeqCst) {
                                interrupt::pause();
                            }
                            println!(" Ready");

                            unsafe {
                                RmmA::invalidate_all();
                            }
                        } else {
                            println!("        CPU Disabled");
                        }
                    }
                }
                _ => (),
            }
        }

        // Unmap trampoline
        let (_frame, _, flush) = unsafe {
            KernelMapper::lock()
                .get_mut()
                .expect("expected kernel page table not to be recursively locked while initializing MADT")
                .unmap_phys(trampoline_page.start_address(), true)
                .expect("failed to unmap trampoline page")
        };
        flush.flush();
    }
}
