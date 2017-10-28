//! # ACPI
//! Code to parse the ACPI tables

use alloc::btree_map::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;

use syscall::io::{Io, Pio};

use spin::RwLock;

use stop::kstop;

use memory::Frame;
use paging::{ActivePageTable, Page, PhysicalAddress, VirtualAddress};
use paging::entry::EntryFlags;

use self::dmar::Dmar;
use self::fadt::Fadt;
use self::madt::Madt;
use self::rsdt::Rsdt;
use self::sdt::Sdt;
use self::xsdt::Xsdt;
use self::hpet::Hpet;
use self::rxsdt::Rxsdt;
use self::rsdp::RSDP;

use self::aml::{parse_aml_table, AmlError, AmlValue};

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
            let result = active_table.map_to(page, frame, EntryFlags::PRESENT | EntryFlags::NO_EXECUTE);
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
                let result = active_table.map_to(page, frame, EntryFlags::PRESENT | EntryFlags::NO_EXECUTE);
                result.flush(active_table);
            }
        }
    }

    sdt
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

    let dsdt = find_sdt("DSDT");
    if dsdt.len() == 1 {
        print!("  DSDT");
        load_table(get_sdt_signature(dsdt[0]));
        init_aml_table(dsdt[0]);
    } else {
        println!("Unable to find DSDT");
        return;
    };

    let ssdts = find_sdt("SSDT");

    for ssdt in ssdts {
        print!("  SSDT");
        load_table(get_sdt_signature(ssdt));
        init_aml_table(ssdt);
    }
}

/// Parse the ACPI tables to gather CPU, interrupt, and timer information
pub unsafe fn init(active_table: &mut ActivePageTable) {
    {
        let mut sdt_ptrs = SDT_POINTERS.write();
        *sdt_ptrs = Some(BTreeMap::new());
    }

    {
        let mut order = SDT_ORDER.write();
        *order = Some(vec!());
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
            let sdt = &*(sdt_address as *const Sdt);

            let signature = get_sdt_signature(sdt);
            if let Some(ref mut ptrs) = *(SDT_POINTERS.write()) {
                ptrs.insert(signature, sdt);
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

type SdtSignature = (String, [u8; 6], [u8; 8]);
pub static SDT_POINTERS: RwLock<Option<BTreeMap<SdtSignature, &'static Sdt>>> = RwLock::new(None);
pub static SDT_ORDER: RwLock<Option<Vec<SdtSignature>>> = RwLock::new(None);

pub fn find_sdt(name: &str) -> Vec<&'static Sdt> {
    let mut sdts: Vec<&'static Sdt> = vec!();

    if let Some(ref ptrs) = *(SDT_POINTERS.read()) {
        for (signature, sdt) in ptrs {
            if signature.0 == name {
                sdts.push(sdt);
            }
        }
    }

    sdts
}

pub fn get_sdt_signature(sdt: &'static Sdt) -> SdtSignature {
    let signature = String::from_utf8(sdt.signature.to_vec()).expect("Error converting signature to string");
    (signature, sdt.oem_id, sdt.oem_table_id)
}

pub fn load_table(signature: SdtSignature) {
    let mut order = SDT_ORDER.write();

    if let Some(ref mut o) = *order {
        o.push(signature);
    }
}

pub fn get_signature_from_index(index: usize) -> Option<SdtSignature> {
    if let Some(ref order) = *(SDT_ORDER.read()) {
        if index < order.len() {
            Some(order[index].clone())
        } else {
            None
        }
    } else {
        None
    }
}

pub fn get_index_from_signature(signature: SdtSignature) -> Option<usize> {
    if let Some(ref order) = *(SDT_ORDER.read()) {
        let mut i = order.len();
        while i > 0 {
            i -= 1;

            if order[i] == signature {
                return Some(i);
            }
        }
    }

    None
}

pub struct Acpi {
    pub fadt: RwLock<Option<Fadt>>,
    pub namespace: RwLock<Option<BTreeMap<String, AmlValue>>>,
    pub hpet: RwLock<Option<Hpet>>,
    pub next_ctx: RwLock<u64>,
}

pub static ACPI_TABLE: Acpi = Acpi {
    fadt: RwLock::new(None),
    namespace: RwLock::new(None),
    hpet: RwLock::new(None),
    next_ctx: RwLock::new(0),
};
