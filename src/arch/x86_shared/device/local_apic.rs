use core::{
    cell::{Cell, SyncUnsafeCell},
    ptr::{read_volatile, write_volatile},
};
use x86::msr::*;

use crate::{
    ipi::IpiKind,
    memory::{PageFlags, PhysicalAddress},
    percpu::PercpuBlock,
};

use crate::{arch::cpuid::cpuid, memory::KernelMapper};

#[derive(Clone, Copy, Debug)]
pub struct ApicId(u32);

impl ApicId {
    pub fn new(inner: u32) -> Self {
        Self(inner)
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}

static LOCAL_APIC: SyncUnsafeCell<LocalApic> = SyncUnsafeCell::new(LocalApic {
    address: 0,
    x2: false,
});

/// Per-CPU state of the local APIC TSC-deadline tick. `IA32_TSC_DEADLINE` is a
/// per-logical-processor MSR (SDM Vol. 3A, 13.5.4.1), so each CPU arms and re-arms its own.
pub struct TscDeadlinePercpu {
    /// TSC ticks between deadline interrupts. Zero until armed.
    period: Cell<u64>,
    /// TSC value the timer is currently armed for. The MSR itself is cleared when the timer
    /// fires (SDM Vol. 3A, 13.5.4.1), so the previous deadline has to be kept here.
    next: Cell<u64>,
}
impl TscDeadlinePercpu {
    pub const fn default() -> Self {
        Self {
            period: Cell::new(0),
            next: Cell::new(0),
        }
    }
}

fn tsc_deadline_percpu() -> &'static TscDeadlinePercpu {
    &PercpuBlock::current().misc_arch_info.tsc_deadline
}

/// Whether this CPU's local APIC timer is armed as its tick.
pub fn has_tsc_deadline_tick() -> bool {
    tsc_deadline_percpu().period.get() != 0
}

/// Matches the `lapic_timer` IDT entry (see `idt.rs`). Any vector in 16..=255 is
/// valid for an LVT entry (SDM Vol. 3A, 13.5.2 "Valid Interrupt Vectors").
const LAPIC_TIMER_VECTOR: u32 = 48;

pub unsafe fn the_local_apic() -> &'static mut LocalApic {
    unsafe { &mut *LOCAL_APIC.get() }
}

pub unsafe fn init(active_table: &mut KernelMapper<true>) {
    unsafe {
        the_local_apic().init(active_table);
    }
}

pub unsafe fn init_ap() {
    unsafe {
        the_local_apic().init_ap();
    }
}

/// Local APIC
pub struct LocalApic {
    pub address: usize,
    pub x2: bool,
}

impl LocalApic {
    unsafe fn init(&mut self, mapper: &mut KernelMapper<true>) {
        unsafe {
            // bits 12:31 contain the physical address, value should not be shifted
            let physaddr = PhysicalAddress::new(rdmsr(IA32_APIC_BASE) as usize & 0xfffff000);
            #[cfg(target_arch = "x86")]
            let virtaddr = rmm::VirtualAddress::new(crate::LAPIC_OFFSET);
            #[cfg(target_arch = "x86_64")]
            let virtaddr = {
                use rmm::Arch;
                crate::memory::RmmA::phys_to_virt(physaddr)
            };

            self.address = virtaddr.data();
            self.x2 = cpuid()
                .get_feature_info()
                .is_some_and(|feature_info| feature_info.has_x2apic());

            if !self.x2 {
                debug!("Detected xAPIC at {:#x}", physaddr.data());
                if let Some((_entry, lvl, _, flush)) = mapper.unmap_phys(virtaddr) {
                    assert_eq!(lvl, 0, "huge page overlapping with lAPIC mapping");

                    // Unmap xAPIC page if already mapped
                    flush.flush();
                }

                mapper
                    .map_phys(virtaddr, physaddr, PageFlags::new().write(true), 0)
                    .expect("failed to map local APIC memory")
                    .flush();
            } else {
                debug!("Detected x2APIC");
            }

            self.init_ap();
        }
    }

    unsafe fn init_ap(&mut self) {
        unsafe {
            if self.x2 {
                wrmsr(IA32_APIC_BASE, rdmsr(IA32_APIC_BASE) | (1 << 10));
                wrmsr(IA32_X2APIC_SIVR, 0x100);
            } else {
                self.write(0xF0, 0x100);
            }
            self.setup_error_int();
            //self.setup_timer();

            PercpuBlock::current()
                .misc_arch_info
                .apic_id_opt
                .set(Some(self.id()));
        }
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        unsafe { read_volatile((self.address + reg as usize) as *const u32) }
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        unsafe {
            write_volatile((self.address + reg as usize) as *mut u32, value);
        }
    }

    pub fn id(&self) -> ApicId {
        ApicId::new(if self.x2 {
            unsafe { rdmsr(IA32_X2APIC_APICID) as u32 }
        } else {
            unsafe { (self.read(0x20) >> 24) & u8::MAX as u32 } // id is contained in bits 24:31
        })
    }

    pub fn version(&self) -> u32 {
        if self.x2 {
            unsafe { rdmsr(IA32_X2APIC_VERSION) as u32 }
        } else {
            unsafe { self.read(0x30) }
        }
    }

    pub fn icr(&self) -> u64 {
        if self.x2 {
            unsafe { rdmsr(IA32_X2APIC_ICR) }
        } else {
            unsafe { ((self.read(0x310) as u64) << 32) | self.read(0x300) as u64 }
        }
    }

    pub fn set_icr(&mut self, value: u64) {
        if self.x2 {
            unsafe {
                wrmsr(IA32_X2APIC_ICR, value);
            }
        } else {
            unsafe {
                const PENDING: u32 = 1 << 12;
                while self.read(0x300) & PENDING == PENDING {
                    core::hint::spin_loop();
                }
                self.write(0x310, (value >> 32) as u32);
                self.write(0x300, value as u32);
                while self.read(0x300) & PENDING == PENDING {
                    core::hint::spin_loop();
                }
            }
        }
    }

    pub fn ipi(&mut self, apic_id: ApicId, kind: IpiKind) {
        let shift = if self.x2 { 32 } else { 56 };
        self.set_icr((u64::from(apic_id.get()) << shift) | 0x40 | kind as u64);
    }
    pub fn ipi_nmi(&mut self, apic_id: ApicId) {
        let shift = if self.x2 { 32 } else { 56 };
        self.set_icr((u64::from(apic_id.get()) << shift) | (1 << 14) | (0b100 << 8));
    }

    pub unsafe fn eoi(&mut self) {
        unsafe {
            if self.x2 {
                wrmsr(IA32_X2APIC_EOI, 0);
            } else {
                self.write(0xB0, 0);
            }
        }
    }
    /// Reads the Error Status Register.
    pub unsafe fn esr(&mut self) -> u32 {
        unsafe {
            if self.x2 {
                // update the ESR to the current state of the local apic.
                wrmsr(IA32_X2APIC_ESR, 0);
                // read the updated value
                rdmsr(IA32_X2APIC_ESR) as u32
            } else {
                self.write(0x280, 0);
                self.read(0x280)
            }
        }
    }
    pub unsafe fn lvt_timer(&mut self) -> u32 {
        unsafe {
            if self.x2 {
                rdmsr(IA32_X2APIC_LVT_TIMER) as u32
            } else {
                self.read(0x320)
            }
        }
    }
    pub unsafe fn set_lvt_timer(&mut self, value: u32) {
        unsafe {
            if self.x2 {
                wrmsr(IA32_X2APIC_LVT_TIMER, u64::from(value));
            } else {
                self.write(0x320, value);
            }
        }
    }
    pub unsafe fn init_count(&mut self) -> u32 {
        unsafe {
            if self.x2 {
                rdmsr(IA32_X2APIC_INIT_COUNT) as u32
            } else {
                self.read(0x380)
            }
        }
    }
    pub unsafe fn set_init_count(&mut self, initial_count: u32) {
        unsafe {
            if self.x2 {
                wrmsr(IA32_X2APIC_INIT_COUNT, u64::from(initial_count));
            } else {
                self.write(0x380, initial_count);
            }
        }
    }
    pub unsafe fn cur_count(&mut self) -> u32 {
        unsafe {
            if self.x2 {
                rdmsr(IA32_X2APIC_CUR_COUNT) as u32
            } else {
                self.read(0x390)
            }
        }
    }
    pub unsafe fn div_conf(&mut self) -> u32 {
        unsafe {
            if self.x2 {
                rdmsr(IA32_X2APIC_DIV_CONF) as u32
            } else {
                self.read(0x3E0)
            }
        }
    }
    pub unsafe fn set_div_conf(&mut self, div_conf: u32) {
        unsafe {
            if self.x2 {
                wrmsr(IA32_X2APIC_DIV_CONF, u64::from(div_conf));
            } else {
                self.write(0x3E0, div_conf);
            }
        }
    }
    pub unsafe fn lvt_error(&mut self) -> u32 {
        unsafe {
            if self.x2 {
                rdmsr(IA32_X2APIC_LVT_ERROR) as u32
            } else {
                self.read(0x370)
            }
        }
    }
    pub unsafe fn set_lvt_error(&mut self, lvt_error: u32) {
        unsafe {
            if self.x2 {
                wrmsr(IA32_X2APIC_LVT_ERROR, u64::from(lvt_error));
            } else {
                self.write(0x370, lvt_error);
            }
        }
    }
    unsafe fn setup_error_int(&mut self) {
        unsafe {
            let vector = 49u32;
            self.set_lvt_error(vector);
        }
    }
}

/// Arm this CPU's local APIC timer in TSC-deadline mode.
///
/// Cloud Hypervisor has no PIT and no HPET, so the periodic tick has to come from
/// the local APIC. `period_ticks` is the TSC delta corresponding to one tick.
pub unsafe fn start_tsc_deadline(period_ticks: u64) -> bool {
    unsafe {
        let supported = cpuid()
            .get_feature_info()
            .is_some_and(|features| features.has_tsc_deadline());
        if !supported || period_ticks == 0 {
            return false;
        }

        let state = tsc_deadline_percpu();
        state.period.set(period_ticks);

        // SDM Vol. 3A, Table 13-2:
        // LVT timer bits 18:17 = 10b selects TSC-deadline mode, bit 16
        // (mask) is left clear.
        the_local_apic().set_lvt_timer(LAPIC_TIMER_VECTOR | (0b10 << 17));

        // SDM Vol. 3A, 13.5.4.1 "TSC-Deadline Mode":
        // In xAPIC mode the memory-mapped LVT write must be ordered against the WRMSR
        // below, by an MFENCE in between. In x2APIC mode the LVT is written with WRMSR
        // and the processor orders it, so no fence is required there.
        if !the_local_apic().x2 {
            core::arch::asm!("mfence", options(nostack, preserves_flags));
        }

        let deadline = x86::time::rdtsc().saturating_add(period_ticks);
        state.next.set(deadline);
        wrmsr(IA32_TSC_DEADLINE, deadline);
        true
    }
}

/// Schedule the next TSC-deadline interrupt one period after the previous deadline.
///
/// The mode is one-shot: the timer disarms itself when it fires, so each write to
/// `IA32_TSC_DEADLINE` yields at most one interrupt (SDM Vol. 3A, 13.5.4.1). Counting from
/// the previous deadline rather than from the current TSC keeps the latency between the
/// deadline expiring and this re-arm from accumulating as drift.
pub unsafe fn rearm_tsc_deadline() {
    unsafe {
        let state = tsc_deadline_percpu();
        let period = state.period.get();
        if period == 0 {
            return;
        }
        let prev = state.next.get();
        let now = x86::time::rdtsc();
        let mut next = prev.saturating_add(period);

        // A deadline at or before the current TSC fires immediately (SDM Vol. 3A, 13.5.4.1).
        // If whole periods were missed, e.g. while the vCPU was descheduled, skip them on the
        // same phase instead of delivering them back to back.
        if next <= now {
            let missed = (now - prev) / period;
            next = prev.saturating_add((missed + 1).saturating_mul(period));
        }

        state.next.set(next);
        wrmsr(IA32_TSC_DEADLINE, next);
    }
}

#[repr(u8)]
pub enum LvtTimerMode {
    OneShot = 0b00,
    Periodic = 0b01,
    TscDeadline = 0b10,
}
