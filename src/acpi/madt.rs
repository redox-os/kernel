use core::mem;

use crate::{
    memory::{allocate_p2frame, Frame},
    paging::{KernelMapper, Page, PageFlags, PhysicalAddress, RmmA, RmmArch, VirtualAddress, PAGE_SIZE},
};

use super::{find_sdt, sdt::Sdt};

use core::sync::atomic::{AtomicU8, Ordering};

use crate::{
    device::local_apic::LOCAL_APIC,
    interrupt,
    start::{kstart_ap, AP_READY, CPU_COUNT},
};

/// The Multiple APIC Descriptor Table
#[derive(Clone, Copy, Debug)]
pub struct Madt {
    sdt: &'static Sdt,
    pub local_address: u32,
    pub flags: u32,
}

const TRAMPOLINE: usize = 0x8000;
static TRAMPOLINE_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trampoline"));

pub static mut MADT: Option<Madt> = None;
pub const FLAG_PCAT: u32 = 1;

impl Madt {
    pub fn init() {
        let madt_sdt = find_sdt("APIC");
        let madt = if madt_sdt.len() == 1 {
            Madt::new(madt_sdt[0])
        } else {
            println!("Unable to find MADT");
            return;
        };

        if let Some(madt) = madt {
            // safe because no APs have been started yet.
            unsafe { MADT = Some(madt) };

            println!("  APIC: {:>08X}: {}", madt.local_address, madt.flags);

            let local_apic = unsafe { &mut LOCAL_APIC };
            let me = local_apic.id() as u8;

            if local_apic.x2 {
                println!("    X2APIC {}", me);
            } else {
                println!("    XAPIC {}: {:>08X}", me, local_apic.address);
            }

            if cfg!(feature = "multi_core") {
                // Map trampoline
                let trampoline_frame = Frame::containing_address(PhysicalAddress::new(TRAMPOLINE));
                let trampoline_page = Page::containing_address(VirtualAddress::new(TRAMPOLINE));
                let (result, page_table_physaddr) = unsafe {
                    //TODO: do not have writable and executable!
                    let mut mapper = KernelMapper::lock();

                    let result = mapper
                        .get_mut()
                        .expect("expected kernel page table not to be recursively locked while initializing MADT")
                        .map_phys(trampoline_page.start_address(), trampoline_frame.start_address(), PageFlags::new().execute(true).write(true))
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
                    println!("      {:?}", madt_entry);
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
                                        .start_address()
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
                                        ap_cpu_id.write(ap_local_apic.id.into());
                                        ap_page_table.write(page_table_physaddr as u64);
                                        ap_stack_start.write(stack_start as u64);
                                        ap_stack_end.write(stack_end as u64);
                                        ap_code.write(kstart_ap as u64);

                                        // TODO: Is this necessary (this fence)?
                                        core::arch::asm!("");
                                    };
                                    AP_READY.store(false, Ordering::SeqCst);

                                    print!("        AP {}:", ap_local_apic.id);

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
                                    while unsafe {
                                        (*ap_ready.cast::<AtomicU8>()).load(Ordering::SeqCst)
                                    } == 0
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
    }

    pub fn new(sdt: &'static Sdt) -> Option<Madt> {
        if &sdt.signature == b"APIC" && sdt.data_len() >= 8 {
            //Not valid if no local address and flags
            let local_address = unsafe { (sdt.data_address() as *const u32).read_unaligned() };
            let flags = unsafe {
                (sdt.data_address() as *const u32)
                    .offset(1)
                    .read_unaligned()
            };

            Some(Madt {
                sdt,
                local_address,
                flags,
            })
        } else {
            None
        }
    }

    pub fn iter(&self) -> MadtIter {
        MadtIter {
            sdt: self.sdt,
            i: 8, // Skip local controller address and flags
        }
    }
}

/// MADT Local APIC
#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct MadtLocalApic {
    /// Processor ID
    pub processor: u8,
    /// Local APIC ID
    pub id: u8,
    /// Flags. 1 means that the processor is enabled
    pub flags: u32,
}

/// MADT I/O APIC
#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct MadtIoApic {
    /// I/O APIC ID
    pub id: u8,
    /// reserved
    _reserved: u8,
    /// I/O APIC address
    pub address: u32,
    /// Global system interrupt base
    pub gsi_base: u32,
}

/// MADT Interrupt Source Override
#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct MadtIntSrcOverride {
    /// Bus Source
    pub bus_source: u8,
    /// IRQ Source
    pub irq_source: u8,
    /// Global system interrupt base
    pub gsi_base: u32,
    /// Flags
    pub flags: u16,
}

/// MADT Entries
#[derive(Debug)]
pub enum MadtEntry {
    LocalApic(&'static MadtLocalApic),
    InvalidLocalApic(usize),
    IoApic(&'static MadtIoApic),
    InvalidIoApic(usize),
    IntSrcOverride(&'static MadtIntSrcOverride),
    InvalidIntSrcOverride(usize),
    Unknown(u8),
}

pub struct MadtIter {
    sdt: &'static Sdt,
    i: usize,
}

impl Iterator for MadtIter {
    type Item = MadtEntry;
    fn next(&mut self) -> Option<Self::Item> {
        if self.i + 1 < self.sdt.data_len() {
            let entry_type = unsafe { *(self.sdt.data_address() as *const u8).add(self.i) };
            let entry_len =
                unsafe { *(self.sdt.data_address() as *const u8).add(self.i + 1) } as usize;

            if self.i + entry_len <= self.sdt.data_len() {
                let item = match entry_type {
                    0 => {
                        if entry_len == mem::size_of::<MadtLocalApic>() + 2 {
                            MadtEntry::LocalApic(unsafe {
                                &*((self.sdt.data_address() + self.i + 2) as *const MadtLocalApic)
                            })
                        } else {
                            MadtEntry::InvalidLocalApic(entry_len)
                        }
                    }
                    1 => {
                        if entry_len == mem::size_of::<MadtIoApic>() + 2 {
                            MadtEntry::IoApic(unsafe {
                                &*((self.sdt.data_address() + self.i + 2) as *const MadtIoApic)
                            })
                        } else {
                            MadtEntry::InvalidIoApic(entry_len)
                        }
                    }
                    2 => {
                        if entry_len == mem::size_of::<MadtIntSrcOverride>() + 2 {
                            MadtEntry::IntSrcOverride(unsafe {
                                &*((self.sdt.data_address() + self.i + 2)
                                    as *const MadtIntSrcOverride)
                            })
                        } else {
                            MadtEntry::InvalidIntSrcOverride(entry_len)
                        }
                    }
                    _ => MadtEntry::Unknown(entry_type),
                };

                self.i += entry_len;

                Some(item)
            } else {
                None
            }
        } else {
            None
        }
    }
}
