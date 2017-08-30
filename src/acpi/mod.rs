//! # ACPI
//! Code to parse the ACPI tables

use core::intrinsics::{atomic_load, atomic_store};
use core::sync::atomic::Ordering;
use collections::btree_map::BTreeMap;
use collections::string::String;
use collections::vec::Vec;
use alloc::boxed::Box;

use syscall::io::{Io, Pio};

use spin::RwLock;

use stop::kstop;

use device::local_apic::LOCAL_APIC;
use interrupt;
use memory::{allocate_frames, Frame};
use paging::{entry, ActivePageTable, Page, PhysicalAddress, VirtualAddress};
use start::{kstart_ap, CPU_COUNT, AP_READY};

use self::dmar::{Dmar, DmarEntry};
use self::fadt::Fadt;
use self::madt::{Madt, MadtEntry};
use self::rsdt::Rsdt;
use self::sdt::Sdt;
use self::xsdt::Xsdt;
use self::hpet::Hpet;
use self::rxsdt::Rxsdt;
use self::rsdp::RSDP;

use self::aml::{is_aml_table, parse_aml_table, AmlError, AmlValue};

pub mod hpet;
mod dmar;
mod fadt;
mod madt;
mod rsdt;
mod sdt;
mod xsdt;
mod aml;
mod rxsdt;
mod rsdp;

const TRAMPOLINE: usize = 0x7E00;
const AP_STARTUP: usize = TRAMPOLINE + 512;

fn get_sdt(sdt_address: usize, active_table: &mut ActivePageTable) -> &'static Sdt {
    {
        let page = Page::containing_address(VirtualAddress::new(sdt_address));
        if active_table.translate_page(page).is_none() {
            let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().get()));
            let result = active_table.map_to(page, frame, entry::PRESENT | entry::NO_EXECUTE);
            result.flush(active_table);
        }
    }

    let sdt = unsafe { &*(sdt_address as *const Sdt) };

    // Map extra SDT frames if required
    {
        let start_page = Page::containing_address(VirtualAddress::new(sdt_address + 4096));
        let end_page = Page::containing_address(VirtualAddress::new(sdt_address + sdt.length as usize));
        for page in Page::range_inclusive(start_page, end_page) {
            if active_table.translate_page(page).is_none() {
                let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().get()));
                let result = active_table.map_to(page, frame, entry::PRESENT | entry::NO_EXECUTE);
                result.flush(active_table);
            }
        }
    }

    sdt
}

fn parse_sdt(sdt: &'static Sdt, active_table: &mut ActivePageTable) {
    print!("  ");
    for &c in sdt.signature.iter() {
        print!("{}", c as char);
    }

    if let Some(fadt) = Fadt::new(sdt) {
        println!(": {:X}", fadt.dsdt);
        
        let dsdt = get_sdt(fadt.dsdt as usize, active_table);
        parse_sdt(dsdt, active_table);
        
        let mut fadt_t = ACPI_TABLE.fadt.write();
        *fadt_t = Some(fadt);
    } else if let Some(madt) = Madt::new(sdt) {
        println!(": {:>08X}: {}", madt.local_address, madt.flags);

        let local_apic = unsafe { &mut LOCAL_APIC };

        let me = local_apic.id() as u8;

        if local_apic.x2 {
            println!("    X2APIC {}", me);
        } else {
            println!("    XAPIC {}: {:>08X}", me, local_apic.address);
        }

        if cfg!(feature = "multi_core"){
            let trampoline_frame = Frame::containing_address(PhysicalAddress::new(TRAMPOLINE));
            let trampoline_page = Page::containing_address(VirtualAddress::new(TRAMPOLINE));

            // Map trampoline
            let result = active_table.map_to(trampoline_page, trampoline_frame, entry::PRESENT | entry::WRITABLE);
            result.flush(active_table);

            for madt_entry in madt.iter() {
                println!("      {:?}", madt_entry);
                match madt_entry {
                    MadtEntry::LocalApic(ap_local_apic) => if ap_local_apic.id == me {
                        println!("        This is my local APIC");
                    } else {
                        if ap_local_apic.flags & 1 == 1 {
                            // Increase CPU ID
                            CPU_COUNT.fetch_add(1, Ordering::SeqCst);

                            // Allocate a stack
                            let stack_start = allocate_frames(64).expect("no more frames in acpi stack_start").start_address().get() + ::KERNEL_OFFSET;
                            let stack_end = stack_start + 64 * 4096;

                            let ap_ready = TRAMPOLINE as *mut u64;
                            let ap_cpu_id = unsafe { ap_ready.offset(1) };
                            let ap_page_table = unsafe { ap_ready.offset(2) };
                            let ap_stack_start = unsafe { ap_ready.offset(3) };
                            let ap_stack_end = unsafe { ap_ready.offset(4) };
                            let ap_code = unsafe { ap_ready.offset(5) };

                            // Set the ap_ready to 0, volatile
                            unsafe { atomic_store(ap_ready, 0) };
                            unsafe { atomic_store(ap_cpu_id, ap_local_apic.id as u64) };
                            unsafe { atomic_store(ap_page_table, active_table.address() as u64) };
                            unsafe { atomic_store(ap_stack_start, stack_start as u64) };
                            unsafe { atomic_store(ap_stack_end, stack_end as u64) };
                            unsafe { atomic_store(ap_code, kstart_ap as u64) };
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
                                let ap_segment = (AP_STARTUP >> 12) & 0xFF;
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
                            while unsafe { atomic_load(ap_ready) } == 0 {
                                interrupt::pause();
                            }
                            print!(" Trampoline...");
                            while ! AP_READY.load(Ordering::SeqCst) {
                                interrupt::pause();
                            }
                            println!(" Ready");

                            active_table.flush_all();
                        } else {
                            println!("        CPU Disabled");
                        }
                    },
                    _ => ()
                }
            }

            // Unmap trampoline
            let (result, _frame) = active_table.unmap_return(trampoline_page, false);
            result.flush(active_table);
        }
    } else if let Some(dmar) = Dmar::new(sdt) {
        println!(": {}: {}", dmar.addr_width, dmar.flags);

        for dmar_entry in dmar.iter() {
            println!("      {:?}", dmar_entry);
            match dmar_entry {
                DmarEntry::Drhd(dmar_drhd) => {
                    let drhd = dmar_drhd.get(active_table);

                    println!("VER: {:X}", drhd.version);
                    println!("CAP: {:X}", drhd.cap);
                    println!("EXT_CAP: {:X}", drhd.ext_cap);
                    println!("GCMD: {:X}", drhd.gl_cmd);
                    println!("GSTS: {:X}", drhd.gl_sts);
                    println!("RT: {:X}", drhd.root_table);
                },
                _ => ()
            }
        }
    } else if let Some(hpet) = Hpet::new(sdt, active_table) {
        println!(": {}", hpet.hpet_number);
        
        let mut hpet_t = ACPI_TABLE.hpet.write();
        *hpet_t = Some(hpet);
    } else if is_aml_table(sdt) {
        match parse_aml_table(sdt) {
            Ok(_) => println!(": Parsed"),
            Err(AmlError::AmlParseError(e)) => println!(": {}", e),
            Err(AmlError::AmlInvalidOpCode) => println!(": Invalid opcode"),
            Err(AmlError::AmlValueError) => println!(": Type constraints or value bounds not met"),
            Err(AmlError::AmlDeferredLoad) => println!(": Deferred load reached top level"),
            Err(AmlError::AmlFatalError(_, _, _)) => {
                println!(": Fatal error occurred");
                unsafe { kstop(); }
            },
            Err(AmlError::AmlHardFatal) => {
                println!(": Fatal error occurred");
                unsafe { kstop(); }
            }
        };
    } else {
        println!(": Unknown");
    }
}

fn init_aml_table(sdt: &'static Sdt) {
    match parse_aml_table(sdt) {
        Ok(_) => println!(": Parsed"),
        Err(AmlError::AmlParseError(e)) => println!(": {}", e),
        Err(AmlError::AmlInvalidOpCode) => println!(": Invalid opcode"),
        Err(AmlError::AmlValueError) => println!(": Type constraints or value bounds not met"),
        Err(AmlError::AmlDeferredLoad) => println!(": Deferred load reached top level"),
        Err(AmlError::AmlFatalError(_, _, _)) => {
            println!(": Fatal error occurred");
            unsafe { kstop(); }
        },
        Err(AmlError::AmlHardFatal) => {
            println!(": Fatal error occurred");
            unsafe { kstop(); }
        }
    }
}

fn init_namespace() {
    {
        let mut namespace = ACPI_TABLE.namespace.write();
        *namespace = Some(BTreeMap::new());
    }

    let dsdt: &'static Sdt = if let Some(ref ptrs) = *(SDT_POINTERS.read()) {
        if let Some(dsdt_sdt) = ptrs.get("DSDT") {
            print!("  DSDT");
            dsdt_sdt
        } else {
            println!("No DSDT found");
            return;
        }
    } else {
        return;
    };

    init_aml_table(dsdt);
    
    let ssdt: &'static Sdt = if let Some(ref ptrs) = *(SDT_POINTERS.read()) {
        if let Some(ssdt_sdt) = ptrs.get("SSDT") {
            print!("  SSDT");
            ssdt_sdt
        } else {
            println!("No SSDT found");
            return;
        }
    } else {
        return;
    };

    init_aml_table(ssdt);
}

/// Parse the ACPI tables to gather CPU, interrupt, and timer information
pub unsafe fn init(active_table: &mut ActivePageTable) {
    {
        let mut sdt_ptrs = SDT_POINTERS.write();
        *sdt_ptrs = Some(BTreeMap::new());
    }
    
    // Search for RSDP
    if let Some(rsdp) = RSDP::get_rsdp(active_table) {
        let rxsdt = get_sdt(rsdp.sdt_address(), active_table);

        for &c in rxsdt.signature.iter() {
            print!("{}", c as char);
        }
        println!(":");

        let rxsdt: Box<Rxsdt + Send + Sync> = if let Some(rsdt) = Rsdt::new(rxsdt) {
            Box::new(rsdt)
        } else if let Some(xsdt) = Xsdt::new(rxsdt) {
            Box::new(xsdt)
        } else {
            println!("UNKNOWN RSDT OR XSDT SIGNATURE");
            return;
        };
        
        rxsdt.map_all(active_table);
        
        for sdt_address in rxsdt.iter() {
            let sdt = unsafe { &*(sdt_address as *const Sdt) };
            
            let signature = String::from_utf8(sdt.signature.to_vec()).expect("Error converting signature to string");
            {
                if let Some(ref mut ptrs) = *(SDT_POINTERS.write()) {
                    ptrs.insert(signature, sdt);
                }
            }
        }

        Fadt::init(active_table);
        Madt::init(active_table);
        Dmar::init(active_table);
        Hpet::init(active_table);
        init_namespace();
    } else {
        println!("NO RSDP FOUND");
    }
}

pub fn set_global_s_state(state: u8) {
    if state == 5 {
        let fadt = ACPI_TABLE.fadt.read();
        
        if let Some(ref fadt) = *fadt {
            let port = fadt.pm1a_control_block as u16;
            let mut val = 1 << 13;

            let namespace = ACPI_TABLE.namespace.read();

            if let Some(ref namespace) = *namespace {
                if let Some(s) = namespace.get("\\_S5") {
                    if let Ok(p) = s.get_as_package() {
                        let slp_typa = p[0].get_as_integer().expect("SLP_TYPa is not an integer");
                        let slp_typb = p[1].get_as_integer().expect("SLP_TYPb is not an integer");
                        
                        println!("Shutdown SLP_TYPa {:X}, SLP_TYPb {:X}", slp_typa, slp_typb);
                        val |= slp_typa as u16;
                        
                        println!("Shutdown with ACPI outw(0x{:X}, 0x{:X})", port, val);
                        Pio::<u16>::new(port).write(val);
                    }
                }
            }
        }
    }
}

pub static SDT_POINTERS: RwLock<Option<BTreeMap<String, &'static Sdt>>> = RwLock::new(None);

pub struct Acpi {
    pub rxsdt: RwLock<Option<Box<Rxsdt + Send + Sync>>>,
    pub fadt: RwLock<Option<Fadt>>,
    pub namespace: RwLock<Option<BTreeMap<String, AmlValue>>>,
    pub hpet: RwLock<Option<Hpet>>,
    pub next_ctx: RwLock<u64>,
}

pub static ACPI_TABLE: Acpi = Acpi {
    rxsdt: RwLock::new(None),
    fadt: RwLock::new(None),
    namespace: RwLock::new(None),
    hpet: RwLock::new(None),
    next_ctx: RwLock::new(0),
};
