use crate::acpi::ACPI_TABLE;
use super::device::{hpet, pit};

pub fn counter() -> u128 {
    if let Some(ref hpet) = *ACPI_TABLE.hpet.read() {
        //TODO: handle rollover?
        //TODO: improve performance

        // Current count
        let counter = unsafe { hpet.base_address.read_u64(hpet::MAIN_COUNTER_OFFSET) };
        // Comparator holds next interrupt count
        let comparator = unsafe { hpet.base_address.read_u64(hpet::T0_COMPARATOR_OFFSET) };
        // Get period in femtoseconds
        let capability = unsafe { hpet.base_address.read_u64(hpet::CAPABILITY_OFFSET) };
        let period_fs = capability >> 32;
        // Calculate divisor
        let divisor = (pit::RATE as u64 * 1_000_000) / period_fs;
        // Calculate last interrupt
        let last_interrupt = comparator.saturating_sub(divisor);
        // Calculate ticks since last interrupt
        let elapsed = counter.saturating_sub(last_interrupt);
        // Calculate nanoseconds since last interrupt
        (elapsed as u128 * period_fs as u128) / 1_000_000
    } else {
        // Read ticks since last interrupt
        let elapsed = unsafe { pit::read() };
        // Calculate nanoseconds since last interrupt
        (elapsed as u128 * pit::PERIOD_FS) / 1_000_000
    }
}
