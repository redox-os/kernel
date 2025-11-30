use crate::memory::KernelMapper;
use core::cell::Cell;

pub mod cpu;
#[cfg(feature = "acpi")]
pub mod hpet;
pub mod ioapic;
pub mod local_apic;
pub mod pic;
pub mod pit;
pub mod serial;
#[cfg(feature = "system76_ec_debug")]
pub mod system76_ec;

#[cfg(feature = "x86_kvm_pv")]
pub mod tsc;

pub unsafe fn init() {
    unsafe {
        pic::init();
        local_apic::init(&mut KernelMapper::lock());

        // Run here for the side-effect of printing if KVM was used to avoid interleaved logs.
        tsc::get_kvm_support();
    }
}
pub unsafe fn init_after_acpi() {
    // this will disable the IOAPIC if needed.
    //ioapic::init(mapper);
}

#[cfg(feature = "acpi")]
unsafe fn init_hpet() -> bool {
    unsafe {
        use crate::acpi::ACPI_TABLE;
        match *ACPI_TABLE.hpet.write() {
            Some(ref mut hpet) => {
                if cfg!(target_arch = "x86") {
                    //TODO: fix HPET on i686
                    warn!("HPET found but implemented on i686");
                    return false;
                }
                hpet::init(hpet)
            }
            _ => false,
        }
    }
}

#[cfg(not(feature = "acpi"))]
unsafe fn init_hpet() -> bool {
    false
}

pub unsafe fn init_noncore() {
    unsafe {
        debug!("Initializing system timer");

        #[cfg(feature = "x86_kvm_pv")]
        if tsc::init() {
            debug!("TSC used as system clock source");
        }

        if init_hpet() {
            debug!("HPET used as system timer");
        } else {
            pit::init();
            debug!("PIT used as system timer");
        }

        debug!("Finished initializing devices");
    }
}

pub unsafe fn init_ap() {
    unsafe {
        local_apic::init_ap();

        #[cfg(feature = "x86_kvm_pv")]
        tsc::init();
    }
}

pub struct ArchPercpuMisc {
    pub apic_id_opt: Cell<Option<local_apic::ApicId>>,
    #[cfg(feature = "x86_kvm_pv")]
    pub tsc_info: tsc::TscPercpu,
}

impl ArchPercpuMisc {
    pub const fn default() -> Self {
        Self {
            apic_id_opt: Cell::new(None),
            #[cfg(feature = "x86_kvm_pv")]
            tsc_info: tsc::TscPercpu::default(),
        }
    }
}
