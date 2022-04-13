use core::sync::atomic::{self, AtomicU64};
use core::intrinsics::{volatile_load, volatile_store};
use x86::cpuid::CpuId;
use x86::msr::*;

use crate::memory::Frame;
use crate::paging::{ActivePageTable, PhysicalAddress, Page, PageFlags, VirtualAddress};

pub static mut LOCAL_APIC: LocalApic = LocalApic {
    address: 0,
    x2: false
};

pub unsafe fn init(active_table: &mut ActivePageTable) {
    LOCAL_APIC.init(active_table);
}

pub unsafe fn init_ap() {
    LOCAL_APIC.init_ap();
}

/// Local APIC
pub struct LocalApic {
    pub address: usize,
    pub x2: bool
}

#[derive(Debug)]
struct NoFreqInfo;

static BSP_APIC_ID: AtomicU64 = AtomicU64::new(0xFFFF_FFFF_FFFF_FFFF);

#[no_mangle]
pub fn bsp_apic_id() -> Option<u32> {
    let value = BSP_APIC_ID.load(atomic::Ordering::SeqCst);
    if value <= u64::from(u32::max_value()) {
        Some(value as u32)
    } else {
        None
    }
}

impl LocalApic {
    unsafe fn init(&mut self, active_table: &mut ActivePageTable) {
        self.address = (rdmsr(IA32_APIC_BASE) as usize & 0xFFFF_0000) + crate::PHYS_OFFSET;
        self.x2 = CpuId::new().get_feature_info().unwrap().has_x2apic();

        if ! self.x2 {
            let page = Page::containing_address(VirtualAddress::new(self.address));
            let frame = Frame::containing_address(PhysicalAddress::new(self.address - crate::PHYS_OFFSET));
            log::info!("Detected xAPIC at {:#x}", frame.start_address().data());
            if active_table.translate_page(page).is_some() {
                // Unmap xAPIC page if already mapped
                let (result, _frame) = active_table.unmap_return(page, true);
                result.flush();
            }
            let result = active_table.map_to(page, frame, PageFlags::new().write(true));
            result.flush();
        } else {
            log::info!("Detected x2APIC");
        }

        self.init_ap();
        BSP_APIC_ID.store(u64::from(self.id()), atomic::Ordering::SeqCst);
    }

    unsafe fn init_ap(&mut self) {
        if self.x2 {
            wrmsr(IA32_APIC_BASE, rdmsr(IA32_APIC_BASE) | 1 << 10);
            wrmsr(IA32_X2APIC_SIVR, 0x100);
        } else {
            self.write(0xF0, 0x100);
        }
        self.setup_error_int();
        //self.setup_timer();
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        volatile_load((self.address + reg as usize) as *const u32)
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        volatile_store((self.address + reg as usize) as *mut u32, value);
    }

    pub fn id(&self) -> u32 {
        if self.x2 {
            unsafe { rdmsr(IA32_X2APIC_APICID) as u32 }
        } else {
            unsafe { self.read(0x20) }
        }
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
            unsafe {
                (self.read(0x310) as u64) << 32 | self.read(0x300) as u64
            }
        }
    }

    pub fn set_icr(&mut self, value: u64) {
        if self.x2 {
            unsafe { wrmsr(IA32_X2APIC_ICR, value); }
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

    pub fn ipi(&mut self, apic_id: usize) {
        let mut icr = 0x4040;
        if self.x2 {
            icr |= (apic_id as u64) << 32;
        } else {
            icr |= (apic_id as u64) << 56;
        }
        self.set_icr(icr);
    }
    // Not used just yet, but allows triggering an NMI to another processor.
    pub fn ipi_nmi(&mut self, apic_id: u32) {
        let shift = if self.x2 { 32 } else { 56 };
        self.set_icr((u64::from(apic_id) << shift) | (1 << 14) | (0b100 << 8));
    }

    pub unsafe fn eoi(&mut self) {
        if self.x2 {
            wrmsr(IA32_X2APIC_EOI, 0);
        } else {
            self.write(0xB0, 0);
        }
    }
    /// Reads the Error Status Register.
    pub unsafe fn esr(&mut self) -> u32 {
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
    pub unsafe fn lvt_timer(&mut self) -> u32 {
        if self.x2 {
            rdmsr(IA32_X2APIC_LVT_TIMER) as u32
        } else {
            self.read(0x320)
        }
    }
    pub unsafe fn set_lvt_timer(&mut self, value: u32) {
        if self.x2 {
            wrmsr(IA32_X2APIC_LVT_TIMER, u64::from(value));
        } else {
            self.write(0x320, value);
        }
    }
    pub unsafe fn init_count(&mut self) -> u32 {
        if self.x2 {
            rdmsr(IA32_X2APIC_INIT_COUNT) as u32
        } else {
            self.read(0x380)
        }
    }
    pub unsafe fn set_init_count(&mut self, initial_count: u32) {
        if self.x2 {
            wrmsr(IA32_X2APIC_INIT_COUNT, u64::from(initial_count));
        } else {
            self.write(0x380, initial_count);
        }
    }
    pub unsafe fn cur_count(&mut self) -> u32 {
        if self.x2 {
            rdmsr(IA32_X2APIC_CUR_COUNT) as u32
        } else {
            self.read(0x390)
        }
    }
    pub unsafe fn div_conf(&mut self) -> u32 {
        if self.x2 {
            rdmsr(IA32_X2APIC_DIV_CONF) as u32
        } else {
            self.read(0x3E0)
        }
    }
    pub unsafe fn set_div_conf(&mut self, div_conf: u32) {
        if self.x2 {
            wrmsr(IA32_X2APIC_DIV_CONF, u64::from(div_conf));
        } else {
            self.write(0x3E0, div_conf);
        }
    }
    pub unsafe fn lvt_error(&mut self) -> u32 {
        if self.x2 {
            rdmsr(IA32_X2APIC_LVT_ERROR) as u32
        } else {
            self.read(0x370)
        }
    }
    pub unsafe fn set_lvt_error(&mut self, lvt_error: u32) {
        if self.x2 {
            wrmsr(IA32_X2APIC_LVT_ERROR, u64::from(lvt_error));
        } else {
            self.write(0x370, lvt_error);
        }
    }
    unsafe fn setup_error_int(&mut self) {
        let vector = 49u32;
        self.set_lvt_error(vector);
    }
}

#[repr(u8)]
pub enum LvtTimerMode {
    OneShot = 0b00,
    Periodic = 0b01,
    TscDeadline = 0b10,
}
