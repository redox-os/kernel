use crate::memory::KernelMapper;

pub mod cpu;
#[cfg(feature = "acpi")]
pub mod hpet;
pub mod ioapic;
pub mod local_apic;
pub mod pic;
pub mod pit;
pub mod rtc;
pub mod serial;
#[cfg(feature = "system76_ec_debug")]
pub mod system76_ec;

#[cfg(feature = "x86_kvm_pv")]
pub mod tsc;

pub unsafe fn init() {
    pic::init();
    local_apic::init(&mut KernelMapper::lock());
}
pub unsafe fn init_after_acpi() {
    // this will disable the IOAPIC if needed.
    //ioapic::init(mapper);
}

#[cfg(feature = "acpi")]
unsafe fn init_hpet() -> bool {
    use crate::acpi::ACPI_TABLE;
    if let Some(ref mut hpet) = *ACPI_TABLE.hpet.write() {
        if cfg!(target_arch = "x86") {
            //TODO: fix HPET on i686
            log::warn!("HPET found but implemented on i686");
            return false;
        }
        hpet::init(hpet)
    } else {
        false
    }
}

#[cfg(not(feature = "acpi"))]
unsafe fn init_hpet() -> bool {
    false
}

pub unsafe fn init_noncore() {
    log::info!("Initializing system timer");

    #[cfg(feature = "x86_kvm_pv")]
    if tsc::init() {
        log::info!("TSC used as system clock source");
    }

    if init_hpet() {
        log::info!("HPET used as system timer");
    } else {
        pit::init();
        log::info!("PIT used as system timer");
    }

    log::info!("Initializing RTC");
    rtc::init();
    log::info!("Initializing serial");
    serial::init();
    log::info!("Finished initializing devices");
}

pub unsafe fn init_ap() {
    local_apic::init_ap();

    #[cfg(feature = "x86_kvm_pv")]
    tsc::init();
}

#[derive(Default)]
pub struct ArchPercpuMisc {
    #[cfg(feature = "x86_kvm_pv")]
    pub tsc_info: tsc::TscPercpu,
}
