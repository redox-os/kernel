use core::sync::atomic::{self, AtomicU64};
use core::intrinsics::{volatile_load, volatile_store};
use x86::cpuid::CpuId;
use x86::msr::*;

use crate::memory::Frame;
use crate::paging::{ActivePageTable, PhysicalAddress, Page, VirtualAddress};
use crate::paging::entry::EntryFlags;
use crate::{interrupt, time};

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
        self.address = (rdmsr(IA32_APIC_BASE) as usize & 0xFFFF_0000) + crate::KERNEL_OFFSET;
        self.x2 = CpuId::new().get_feature_info().unwrap().has_x2apic();

        if ! self.x2 {
            let page = Page::containing_address(VirtualAddress::new(self.address));
            let frame = Frame::containing_address(PhysicalAddress::new(self.address - crate::KERNEL_OFFSET));
            let result = active_table.map_to(page, frame, EntryFlags::PRESENT | EntryFlags::WRITABLE | EntryFlags::NO_EXECUTE);
            result.flush(active_table);
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
                while self.read(0x300) & 1 << 12 == 1 << 12 {}
                self.write(0x310, (value >> 32) as u32);
                self.write(0x300, value as u32);
                while self.read(0x300) & 1 << 12 == 1 << 12 {}
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
    unsafe fn setup_timer(&mut self) -> Result<(), NoFreqInfo> {
        // TODO: Get the correct frequency, use the local apic timer instead of the PIT.
        let cpuid = CpuId::new();
        let hardcoded_frequency_in_hz = cpuid.get_tsc_info().map(|tsc| {
            if tsc.numerator() != 0 {
                // The core crystal clock frequency, in hertz.
                Some(tsc.tsc_frequency())
            } else { None }
        }).or_else(|| {
            cpuid.get_processor_frequency_info().map(|freq| {
                let bus_freq = freq.bus_frequency();
                if bus_freq != 0 {
                    Some(u64::from(bus_freq) * 1_000_000)
                } else { None }
            })
        }).flatten();

        let frequency_in_hz = hardcoded_frequency_in_hz.unwrap_or_else(|| {
            let (numer, denom) = self.determine_freq();
            let quotient = numer / denom;
            quotient as u64
        });

        let most_suitable_divider = most_suitable_divider(frequency_in_hz);

        println!("FREQUENCY: {}", frequency_in_hz);
        println!("MOST_SUIT_DIV: {}", most_suitable_divider);

        let div_conf_value = most_suitable_divider; // divide by 128
        self.set_div_conf(div_conf_value.into());

        let init_count_value = 1_000_000;
        self.set_init_count(init_count_value);

        let lvt_timer_value = ((LvtTimerMode::Periodic as u32) << 17) | 48u32;
        self.set_lvt_timer(lvt_timer_value);

        Ok(())
    }
    /// Determine the APIC timer frequency, if the info wasn't already retrieved directly from the
    /// CPU.
    unsafe fn determine_freq(&mut self) -> (u128, u128) {
        let old_time = time::monotonic();
        let (old_time_s, old_time_ns) = old_time;

        super::super::idt::IDT[32].set_func(super::super::interrupt::irq::calib_pit);

        self.set_div_conf(0b1011); // divide by 1
        self.set_lvt_timer((LvtTimerMode::OneShot as u32) << 17 | 48);

        // enable both the apic timer and the pit timer simultaneously
        interrupt::enable_and_nop();

        self.set_init_count(0xFFFF_FFFF);

        let mut time;

        'halt: loop {
            time = time::monotonic();
            if time.0 > old_time_s || time.1 - old_time_ns > 10_000_000 {
                break 'halt;
            }
            x86::halt();
        }

        let (time_s, time_ns) = time;

        let lvt_timer = self.lvt_timer();
        self.set_lvt_timer(lvt_timer | 1 << 16);

        let current_count = self.cur_count();

        let lvt_timer_difference = 0xFFFF_FFFF - current_count;
        let (s_difference, ns_difference) = (time_s - old_time_s, time_ns - old_time_ns);

        let freq_numer = u128::from(lvt_timer_difference) * 1_000_000_000; // multiply with a billion since we're dividing by nanoseconds.
        let freq_denom_in_s = u128::from(s_difference) * 1_000_000_000 + u128::from(ns_difference);

        super::super::idt::IDT[32].set_func(super::super::interrupt::irq::pit);

        (freq_numer, freq_denom_in_s)
    }
}

#[repr(u8)]
pub enum LvtTimerMode {
    OneShot = 0b00,
    Periodic = 0b01,
    TscDeadline = 0b10,
}

/// Find the most suitable divider configuration value, which is useful if the reported frequency
/// is way too high to actually be useful.
fn most_suitable_divider(freq: u64) -> u8 {
    // the current scheduler switches process about every 40 µs, with 4 µs per tick.
    let quotient = (freq * 1000) / 2_000_000_000;
    if quotient == 0 {
        // the frequency is way to low, so the pit should be used
        println!("Suboptimal APIC timer frequency");
        0b1011 // divide by 1
    } else if quotient == 1 {
        // the frequency closely matches the requested frequency, so use divider 1
        0b1011
    } else if quotient < 4 {
        0b0000 // divider 2
    } else if quotient < 8 {
        0b0001 // divider 4
    } else if quotient < 16 {
        0b0010 // divider 8
    } else if quotient < 32 {
        0b0011 // divider 16
    } else if quotient < 64 {
        0b1001 // divider 64
    } else {
        0b1010 // divider 128
    }
}
