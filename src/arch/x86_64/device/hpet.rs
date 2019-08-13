use crate::acpi::hpet::Hpet;

static LEG_RT_CNF: u64 = 2;
static ENABLE_CNF: u64 = 1;

static TN_VAL_SET_CNF: u64 = 0x40;
static TN_TYPE_CNF: u64 = 0x08;
static TN_INT_ENB_CNF: u64 = 0x04;

static CAPABILITY_OFFSET: usize = 0x00;
static GENERAL_CONFIG_OFFSET: usize = 0x10;
// static GENERAL_INTERRUPT_OFFSET: usize = 0x20;
// static MAIN_COUNTER_OFFSET: usize = 0xF0;
// static NUM_TIMER_CAP_MASK: u64 = 0x0f00;
static LEG_RT_CAP: u64 = 0x8000;
static T0_CONFIG_CAPABILITY_OFFSET: usize = 0x100;
static T0_COMPARATOR_OFFSET: usize = 0x108;

static PER_INT_CAP: u64 = 0x10;

pub unsafe fn init(hpet: &mut Hpet) -> bool {
    let capability = hpet.base_address.read_u64(CAPABILITY_OFFSET);
    if capability & LEG_RT_CAP == 0 {
        return false;
    }

    let counter_clk_period_fs = capability >> 32;
    let desired_fs_period: u64 = 2_250_286 * 1_000_000;

    let clk_periods_per_kernel_tick: u64 = desired_fs_period / counter_clk_period_fs;

    let t0_capabilities = hpet.base_address.read_u64(T0_CONFIG_CAPABILITY_OFFSET);
    if t0_capabilities & PER_INT_CAP == 0 {
        return false;
    }

    let t0_config_word: u64 = TN_VAL_SET_CNF | TN_TYPE_CNF | TN_INT_ENB_CNF;
    hpet.base_address.write_u64(T0_CONFIG_CAPABILITY_OFFSET, t0_config_word);
    hpet.base_address.write_u64(T0_COMPARATOR_OFFSET, clk_periods_per_kernel_tick);
    // set accumulator value
    hpet.base_address.write_u64(T0_COMPARATOR_OFFSET, clk_periods_per_kernel_tick);
    // set interval

    let enable_word: u64 = hpet.base_address.read_u64(GENERAL_CONFIG_OFFSET) | LEG_RT_CNF | ENABLE_CNF;
    hpet.base_address.write_u64(GENERAL_CONFIG_OFFSET, enable_word);
    // Enable interrupts from the HPET

    true
}
