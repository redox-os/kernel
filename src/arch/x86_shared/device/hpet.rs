//! <https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/software-developers-hpet-spec-1-0a.pdf>

use super::pit;
use crate::acpi::hpet::Hpet;
use core::time::Duration;

const LEG_RT_CNF: u64 = 2;
const ENABLE_CNF: u64 = 1;

const TN_VAL_SET_CNF: u64 = 0x40;
const TN_TYPE_CNF: u64 = 0x08;
const TN_INT_ENB_CNF: u64 = 0x04;

pub(crate) const CAPABILITY_OFFSET: usize = 0x00;
const GENERAL_CONFIG_OFFSET: usize = 0x10;
const GENERAL_INTERRUPT_OFFSET: usize = 0x20;
pub(crate) const MAIN_COUNTER_OFFSET: usize = 0xF0;
// const NUM_TIMER_CAP_MASK: u64 = 0x0f00;
const LEG_RT_CAP: u64 = 0x8000;
const T0_CONFIG_CAPABILITY_OFFSET: usize = 0x100;
pub(crate) const T0_COMPARATOR_OFFSET: usize = 0x108;

const PER_INT_CAP: u64 = 0x10;

pub unsafe fn init(hpet: &mut Hpet) -> bool {
    println!("HPET @ {:#x}", { hpet.base_address.address });
    debug_caps(hpet);

    println!("HPET Before Init");
    debug_config(hpet);

    // Disable HPET
    {
        let mut config_word = hpet.read_u64(GENERAL_CONFIG_OFFSET);
        config_word &= !(LEG_RT_CNF | ENABLE_CNF);
        hpet.write_u64(GENERAL_CONFIG_OFFSET, config_word);
    }

    let capability = hpet.read_u64(CAPABILITY_OFFSET);
    if capability & LEG_RT_CAP == 0 {
        log::warn!("HPET missing capability LEG_RT_CAP");
        return false;
    }

    let period_fs = capability >> 32;
    let divisor = (pit::RATE as u64 * 1_000_000) / period_fs;

    let t0_capabilities = hpet.read_u64(T0_CONFIG_CAPABILITY_OFFSET);
    if t0_capabilities & PER_INT_CAP == 0 {
        log::warn!("HPET T0 missing capability PER_INT_CAP");
        return false;
    }

    let counter = hpet.read_u64(MAIN_COUNTER_OFFSET);

    let t0_config_word: u64 = TN_VAL_SET_CNF | TN_TYPE_CNF | TN_INT_ENB_CNF;
    hpet.write_u64(T0_CONFIG_CAPABILITY_OFFSET, t0_config_word);
    // set accumulator value
    hpet.write_u64(T0_COMPARATOR_OFFSET, counter + divisor);
    // set interval
    hpet.write_u64(T0_COMPARATOR_OFFSET, divisor);

    // Enable interrupts from the HPET
    {
        let mut config_word: u64 = hpet.read_u64(GENERAL_CONFIG_OFFSET);
        config_word |= LEG_RT_CNF | ENABLE_CNF;
        hpet.write_u64(GENERAL_CONFIG_OFFSET, config_word);
    }

    println!("HPET After Init");
    debug_config(hpet);

    true
}

unsafe fn debug_caps(hpet: &mut Hpet) {
    let capability = hpet.read_u64(CAPABILITY_OFFSET);
    println!("  caps: {:#x}", capability);
    println!(
        "    clock period: {:?}",
        Duration::from_nanos((capability >> 32) / 1_000_000)
    );
    println!(
        "    ID: {:#x} revision: {}",
        (capability >> 16) as u16,
        capability as u8
    );
    println!(
        "    LEG_RT_CAP: {} COUNT_SIZE_CAP: {}",
        capability & (1 << 15) == (1 << 15),
        capability & (1 << 13) == (1 << 13)
    );
    // The NUM_TIM_CAP field contains the index of the last timer.
    // Add 1 to get the amount of timers.
    println!("    timers: {}", (capability >> 8) as u8 & 0x1F + 1);

    let t0_capabilities = hpet.read_u64(T0_CONFIG_CAPABILITY_OFFSET);
    println!(
        "  T0 interrupt routing: {:#x}",
        (t0_capabilities >> 32) as u32
    );
}

unsafe fn debug_config(hpet: &mut Hpet) {
    let config_word = hpet.read_u64(GENERAL_CONFIG_OFFSET);
    println!("  config: {:#x}", config_word);

    let interrupt_status = hpet.read_u64(GENERAL_INTERRUPT_OFFSET);
    println!("  interrupt status: {:#x}", interrupt_status);

    let counter = hpet.read_u64(MAIN_COUNTER_OFFSET);
    println!("  counter: {:#x}", counter);

    let t0_capabilities = hpet.read_u64(T0_CONFIG_CAPABILITY_OFFSET);
    println!("  T0 flags: {:#x}", t0_capabilities as u32);

    let t0_comparator = hpet.read_u64(T0_COMPARATOR_OFFSET);
    println!("  T0 comparator: {:#x}", t0_comparator);
}
