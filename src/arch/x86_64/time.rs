use crate::acpi::ACPI_TABLE;
use super::device::{hpet, pit};

pub fn counter() -> u128 {
    if let Some(ref hpet) = *ACPI_TABLE.hpet.read() {
        let capability = unsafe { hpet.base_address.read_u64(hpet::CAPABILITY_OFFSET) };
        let period_fs = (capability >> 32) as u128;
        let counter = unsafe { hpet.base_address.read_u64(hpet::MAIN_COUNTER_OFFSET) };
        (counter as u128 * period_fs) / 1_000_000
    } else {
        // 1.193182 MHz PIT is approximately 838.095 nanoseconds
        let period_ns = 838;
        let counter = unsafe { pit::read() };
        counter as u128 * period_ns
    }
}
