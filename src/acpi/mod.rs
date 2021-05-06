//! # ACPI
//! Code to parse the ACPI tables

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;

use spin::{Once, RwLock};

use crate::log::info;
use crate::memory::Frame;
use crate::paging::{ActivePageTable, Page, PageFlags, PhysicalAddress, VirtualAddress};

use self::madt::Madt;
use self::rsdt::Rsdt;
use self::sdt::Sdt;
use self::xsdt::Xsdt;
use self::hpet::Hpet;
use self::rxsdt::Rxsdt;
use self::rsdp::RSDP;

pub mod hpet;
pub mod madt;
mod rsdt;
pub mod sdt;
mod xsdt;
mod rxsdt;
mod rsdp;

pub fn get_sdt(sdt_address: usize, active_table: &mut ActivePageTable) -> &'static Sdt {
    {
        let page = Page::containing_address(VirtualAddress::new(sdt_address));
        if active_table.translate_page(page).is_none() {
            let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().data()));
            let result = active_table.map_to(page, frame, PageFlags::new());
            result.flush();
        }
    }

    let sdt = unsafe { &*(sdt_address as *const Sdt) };

    // Map extra SDT frames if required
    {
        let start_page = Page::containing_address(VirtualAddress::new(sdt_address + 4096));
        let end_page = Page::containing_address(VirtualAddress::new(sdt_address + sdt.length as usize));
        for page in Page::range_inclusive(start_page, end_page) {
            if active_table.translate_page(page).is_none() {
                let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().data()));
                let result = active_table.map_to(page, frame, PageFlags::new());
                result.flush();
            }
        }
    }

    sdt
}

pub enum RxsdtEnum {
    Rsdt(Rsdt),
    Xsdt(Xsdt),
}
impl Rxsdt for RxsdtEnum {
    fn iter(&self) -> Box<dyn Iterator<Item = usize>> {
        match self {
            Self::Rsdt(rsdt) => <Rsdt as Rxsdt>::iter(rsdt),
            Self::Xsdt(xsdt) => <Xsdt as Rxsdt>::iter(xsdt),
        }
    }
}

pub static RXSDT_ENUM: Once<RxsdtEnum> = Once::new();

/// Parse the ACPI tables to gather CPU, interrupt, and timer information
pub unsafe fn init(active_table: &mut ActivePageTable, already_supplied_rsdps: Option<(u64, u64)>) {
    {
        let mut sdt_ptrs = SDT_POINTERS.write();
        *sdt_ptrs = Some(BTreeMap::new());
    }

    // Search for RSDP
    if let Some(rsdp) = RSDP::get_rsdp(active_table, already_supplied_rsdps) {
        info!("RSDP: {:?}", rsdp);
        let rxsdt = get_sdt(rsdp.sdt_address(), active_table);

        for &c in rxsdt.signature.iter() {
            print!("{}", c as char);
        }
        println!(":");

        let rxsdt = if let Some(rsdt) = Rsdt::new(rxsdt) {
            let mut initialized = false;

            let rsdt = RXSDT_ENUM.call_once(|| {
                initialized = true;

                RxsdtEnum::Rsdt(rsdt)
            });

            if !initialized {
                log::error!("RXSDT_ENUM already initialized");
            }

            rsdt
        } else if let Some(xsdt) = Xsdt::new(rxsdt) {
            let mut initialized = false;

            let xsdt = RXSDT_ENUM.call_once(|| {
                initialized = true;

                RxsdtEnum::Xsdt(xsdt)
            });
            if !initialized {
                log::error!("RXSDT_ENUM already initialized");
            }

            xsdt
        } else {
            println!("UNKNOWN RSDT OR XSDT SIGNATURE");
            return;
        };

        // TODO: Don't touch ACPI tables in kernel?

        rxsdt.map_all(active_table);

        for sdt_address in rxsdt.iter() {
            let sdt = &*(sdt_address as *const Sdt);

            let signature = get_sdt_signature(sdt);
            if let Some(ref mut ptrs) = *(SDT_POINTERS.write()) {
                ptrs.insert(signature, sdt);
            }
        }

        // TODO: Enumerate processors in userspace, and then provide an ACPI-independent interface
        // to initialize enumerated processors to userspace?
        Madt::init(active_table);
        // TODO: Let userspace setup HPET, and then provide an interface to specify which timer to
        // use?
        Hpet::init(active_table);
    } else {
        println!("NO RSDP FOUND");
    }
}

pub type SdtSignature = (String, [u8; 6], [u8; 8]);
pub static SDT_POINTERS: RwLock<Option<BTreeMap<SdtSignature, &'static Sdt>>> = RwLock::new(None);

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

pub struct Acpi {
    pub hpet: RwLock<Option<Hpet>>,
    pub next_ctx: RwLock<u64>,
}

pub static ACPI_TABLE: Acpi = Acpi {
    hpet: RwLock::new(None),
    next_ctx: RwLock::new(0),
};
