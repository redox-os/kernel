use spin::Mutex;

use crate::{memory::KernelMapper, percpu::PercpuBlock};
use core::{
    cell::Cell,
    sync::atomic::{AtomicBool, Ordering},
};

pub mod cpu;
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

/// Set when the BSP ticks from its local APIC timer. Each AP then arms its own in
/// `init_ap_timer` instead of being driven by `IpiKind::Pit`.
static LAPIC_TICK: AtomicBool = AtomicBool::new(false);

/// Set if an AP could not arm its own local APIC timer, so the BSP still has to send
/// `IpiKind::Pit` for it.
pub static AP_NEEDS_PIT_IPI: AtomicBool = AtomicBool::new(false);

pub unsafe fn init() {
    unsafe {
        pic::init();
        local_apic::init(&mut KernelMapper::lock_rw());

        // Run here for the side effect of printing if KVM was used to avoid interleaved logs.
        #[cfg(feature = "x86_kvm_pv")]
        tsc::get_kvm_support();
    }
}
pub unsafe fn init_after_acpi() {
    // `pic::init` has already selected the 8259. `ioapic::init` switches to
    // the I/O APIC only when the MADT says there is no PC-AT dual-8259, which
    // is Cloud Hypervisor. QEMU q35 sets PCAT_COMPAT and stays on the PIC.
    unsafe {
        ioapic::init();
    }
}

unsafe fn init_hpet() -> bool {
    if cfg!(not(feature = "acpi")) {
        return false;
    }

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

pub unsafe fn init_noncore() {
    unsafe {
        debug!("Initializing system timer");

        #[cfg(feature = "x86_kvm_pv")]
        if tsc::init() {
            debug!("TSC used as system clock source");
        }

        if init_hpet() {
            debug!("HPET used as system timer");
        } else if start_apic_timer() {
            LAPIC_TICK.store(true, Ordering::Relaxed);
            debug!("Local APIC TSC-deadline timer used as system timer");
        } else {
            pit::init();
            debug!("PIT used as system timer");
        }

        debug!("Finished initializing devices");
    }
}

fn start_apic_timer() -> bool {
    #[cfg(feature = "x86_kvm_pv")]
    {
        if let Some(ticks) = tsc::tsc_ticks_for_ns(pit::RATE) {
            return unsafe { local_apic::start_tsc_deadline(ticks) };
        }
    }
    false
}

/// Arm this AP's local APIC timer if the BSP ticks from its own.
///
/// APs are started from `acpi::init_after_mem`, before the BSP picks its timer in
/// `init_noncore`, so this has to run later, once the AP has seen `BSP_READY`.
pub unsafe fn init_ap_timer() {
    if !LAPIC_TICK.load(Ordering::Relaxed) {
        return;
    }
    if !start_apic_timer() {
        warn!(
            "CPU {}: no local APIC TSC-deadline timer, ticking from BSP IPIs",
            PercpuBlock::current().cpu_id
        );
        AP_NEEDS_PIT_IPI.store(true, Ordering::Relaxed);
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
    pub tsc_deadline: local_apic::TscDeadlinePercpu,
    pub idt: Mutex<Option<&'static mut crate::arch::idt::Idt>>,
}

impl ArchPercpuMisc {
    pub const fn default() -> Self {
        Self {
            apic_id_opt: Cell::new(None),
            #[cfg(feature = "x86_kvm_pv")]
            tsc_info: tsc::TscPercpu::default(),
            tsc_deadline: local_apic::TscDeadlinePercpu::default(),
            idt: Mutex::new(None),
        }
    }
}
