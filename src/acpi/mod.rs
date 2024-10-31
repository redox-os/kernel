//! # ACPI
//! Code to parse the ACPI tables

use alloc::{boxed::Box, string::String, vec::Vec};

use hashbrown::HashMap;
use spin::{Once, RwLock};

use log::info;

use crate::{
    memory::KernelMapper,
    paging::{PageFlags, PhysicalAddress, RmmA, RmmArch},
};

use self::{hpet::Hpet, madt::Madt, rsdp::RSDP, rsdt::Rsdt, rxsdt::Rxsdt, sdt::Sdt, xsdt::Xsdt};

#[cfg(target_arch = "aarch64")]
mod gtdt;
pub mod hpet;
pub mod madt;
mod rsdp;
mod rsdt;
mod rxsdt;
pub mod sdt;
#[cfg(target_arch = "aarch64")]
mod spcr;
mod xsdt;

unsafe fn map_linearly(addr: PhysicalAddress, len: usize, mapper: &mut crate::paging::PageMapper) {
    let base = PhysicalAddress::new(crate::paging::round_down_pages(addr.data()));
    let aligned_len = crate::paging::round_up_pages(len + (addr.data() - base.data()));

    for page_idx in 0..aligned_len / crate::memory::PAGE_SIZE {
        let (_, flush) = mapper
            .map_linearly(
                base.add(page_idx * crate::memory::PAGE_SIZE),
                PageFlags::new(),
            )
            .expect("failed to linearly map SDT");
        flush.flush();
    }
}

pub fn get_sdt(sdt_address: usize, mapper: &mut KernelMapper) -> &'static Sdt {
    let mapper = mapper
        .get_mut()
        .expect("KernelMapper mapper locked re-entrant in get_sdt");

    let physaddr = PhysicalAddress::new(sdt_address);

    let sdt;

    unsafe {
        const SDT_SIZE: usize = core::mem::size_of::<Sdt>();
        map_linearly(physaddr, SDT_SIZE, mapper);

        sdt = &*(RmmA::phys_to_virt(physaddr).data() as *const Sdt);

        map_linearly(
            physaddr.add(SDT_SIZE),
            sdt.length as usize - SDT_SIZE,
            mapper,
        );
    }
    sdt
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GenericAddressStructure {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
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
pub unsafe fn init(already_supplied_rsdp: Option<*const u8>) {
    {
        let mut sdt_ptrs = SDT_POINTERS.write();
        *sdt_ptrs = Some(HashMap::new());
    }

    // Search for RSDP
    let rsdp_opt = RSDP::get_rsdp(&mut KernelMapper::lock(), already_supplied_rsdp);

    if let Some(rsdp) = rsdp_opt {
        info!("RSDP: {:?}", rsdp);
        let rxsdt = get_sdt(rsdp.sdt_address(), &mut KernelMapper::lock());

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

        for sdt in rxsdt.iter() {
            get_sdt(sdt, &mut KernelMapper::lock());
        }

        for sdt_address in rxsdt.iter() {
            let sdt = &*((sdt_address + crate::PHYS_OFFSET) as *const Sdt);

            let signature = get_sdt_signature(sdt);
            if let Some(ref mut ptrs) = *(SDT_POINTERS.write()) {
                ptrs.insert(signature, sdt);
            }
        }

        //TODO: support this on any arch
        #[cfg(target_arch = "aarch64")]
        spcr::Spcr::init();
        // TODO: Enumerate processors in userspace, and then provide an ACPI-independent interface
        // to initialize enumerated processors to userspace?
        Madt::init();
        // TODO: Let userspace setup HPET, and then provide an interface to specify which timer to
        // use?
        Hpet::init();
        #[cfg(target_arch = "aarch64")]
        gtdt::Gtdt::init();
    } else {
        println!("NO RSDP FOUND");
    }
}

pub type SdtSignature = (String, [u8; 6], [u8; 8]);
pub static SDT_POINTERS: RwLock<Option<HashMap<SdtSignature, &'static Sdt>>> = RwLock::new(None);

pub fn find_sdt(name: &str) -> Vec<&'static Sdt> {
    let mut sdts: Vec<&'static Sdt> = vec![];

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
    let signature =
        String::from_utf8(sdt.signature.to_vec()).expect("Error converting signature to string");
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
