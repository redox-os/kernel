use core::intrinsics::{volatile_load, volatile_store};

use memory::Frame;
use paging::{entry, ActivePageTable, PhysicalAddress, Page, VirtualAddress};

use acpi::hpet::Hpet;

pub static mut HPET: HpetDevice = HpetDevice {
    capability_addr: 0,
    general_config_addr: 0,
    general_interrupt_addr: 0,
    main_counter_addr: 0,
    t0_config_capability_addr: 0,
    t0_comparator_addr: 0
};

static LEG_RT_CNF: u64 = 2;
static ENABLE_CNF: u64 = 1;

static TN_VAL_SET_CNF: u64 = 0x40;
static TN_TYPE_CNF: u64 = 0x08;
static TN_INT_ENB_CNF: u64 = 0x04;

pub struct HpetDevice {
    capability_addr: usize,
    general_config_addr: usize,
    general_interrupt_addr: usize,
    main_counter_addr: usize,
    t0_config_capability_addr: usize,
    t0_comparator_addr: usize
}

pub unsafe fn init(hpet: &Hpet, active_table: &mut ActivePageTable) {
    HPET.init(hpet, active_table);
}

impl HpetDevice {
    unsafe fn init(&mut self, hpet: &Hpet, active_table: &mut ActivePageTable) {
        let base_address = hpet.base_address.address as usize;

        self.capability_addr = base_address;
        self.general_config_addr = base_address + 0x10;
        self.general_interrupt_addr = base_address + 0x20;
        self.main_counter_addr = base_address + 0xF0;

        self.t0_config_capability_addr = base_address + 0x100;
        self.t0_comparator_addr = base_address + 0x108;

        {
            let page = Page::containing_address(VirtualAddress::new(base_address));
            let frame = Frame::containing_address(PhysicalAddress::new(base_address));
            let result = active_table.map_to(page, frame, entry::PRESENT | entry::WRITABLE | entry::NO_EXECUTE);
            result.flush(active_table);
        }

        println!("HPET mapped");

        let counter_clk_period_fs = self.get_counter_clock_period();
        let desired_fs_period: u64 = 2250286 * 1000000;

        let clk_periods_per_kernel_tick: u64 = desired_fs_period / counter_clk_period_fs;

        let enable_word: u64 = volatile_load(self.general_config_addr as *const u64)
            | LEG_RT_CNF | ENABLE_CNF;

        volatile_store(self.general_config_addr as *mut u64, enable_word);
        // Enable interrupts from the HPET

        let t0_config_word: u64 = TN_VAL_SET_CNF | TN_TYPE_CNF | TN_INT_ENB_CNF;
        volatile_store(self.t0_config_capability_addr as *mut u64, t0_config_word);

        volatile_store(self.t0_comparator_addr as *mut u64, clk_periods_per_kernel_tick);
    }

    pub fn get_counter_clock_period(&self) -> u64 {
        unsafe { volatile_load(self.capability_addr as *const u64) >> 32 }
    }
    
    pub fn get_main_counter(&self) -> u64 {
        unsafe { volatile_load(self.main_counter_addr as *const u64) }
    }
}
