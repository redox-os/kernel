use core::{
    cell::SyncUnsafeCell,
    ptr::{read_volatile, write_volatile},
};
use x86::msr::*;

use crate::{
    ipi::IpiKind,
    paging::{PageFlags, PhysicalAddress},
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
pub unsafe fn the_local_apic() -> &'static mut LocalApic {
    unsafe { &mut *LOCAL_APIC.get() }
}

pub unsafe fn init(active_table: &mut KernelMapper) {
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
    unsafe fn init(&mut self, mapper: &mut KernelMapper) {
        unsafe {
            let mapper = mapper.get_mut().expect(
                "expected KernelMapper not to be locked re-entrant while initializing LAPIC",
            );

            let physaddr = PhysicalAddress::new(rdmsr(IA32_APIC_BASE) as usize & 0xFFFF_0000);
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
                info!("Detected xAPIC at {:#x}", physaddr.data());
                if let Some((_entry, _, flush)) = mapper.unmap_phys(virtaddr, true) {
                    // Unmap xAPIC page if already mapped
                    flush.flush();
                }
                mapper
                    .map_phys(virtaddr, physaddr, PageFlags::new().write(true))
                    .expect("failed to map local APIC memory")
                    .flush();
            } else {
                info!("Detected x2APIC");
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
            unsafe { self.read(0x20) }
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

#[repr(u8)]
pub enum LvtTimerMode {
    OneShot = 0b00,
    Periodic = 0b01,
    TscDeadline = 0b10,
}
