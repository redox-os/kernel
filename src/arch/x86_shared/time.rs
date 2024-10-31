#[cfg(feature = "acpi")]
use super::device::hpet;
use super::device::pit;

pub fn monotonic_absolute() -> u128 {
    // The paravirtualized TSC is already guaranteed to be monotonic, and thus doesn't need to be
    // readjusted.
    #[cfg(feature = "x86_kvm_pv")]
    if let Some(ns) = super::device::tsc::monotonic_absolute() {
        return ns;
    }

    *crate::time::OFFSET.lock() + hpet_or_pit()
}
fn hpet_or_pit() -> u128 {
    #[cfg(feature = "acpi")]
    if let Some(ref hpet) = *crate::acpi::ACPI_TABLE.hpet.read() {
        //TODO: handle rollover?
        //TODO: improve performance

        // Current count
        let counter = unsafe { hpet.read_u64(hpet::MAIN_COUNTER_OFFSET) };
        // Comparator holds next interrupt count
        let comparator = unsafe { hpet.read_u64(hpet::T0_COMPARATOR_OFFSET) };
        // Get period in femtoseconds
        let capability = unsafe { hpet.read_u64(hpet::CAPABILITY_OFFSET) };

        // There seems to be a bug in qemu on macos that causes the calculation to produce 0 for
        // period_fs and hence a divide by zero calculating the divisor - workaround it while we
        // try and get a fix from qemu: https://gitlab.com/qemu-project/qemu/-/issues/1570
        let mut period_fs = capability >> 32;
        if period_fs == 0 {
            period_fs = 10_000_000;
        }

        // Calculate divisor
        let divisor = (pit::RATE as u64 * 1_000_000) / period_fs;
        // Calculate last interrupt
        let last_interrupt = comparator.saturating_sub(divisor);
        // Calculate ticks since last interrupt
        let elapsed = counter.saturating_sub(last_interrupt);
        // Calculate nanoseconds since last interrupt
        return (elapsed as u128 * period_fs as u128) / 1_000_000;
    }
    // Read ticks since last interrupt
    let elapsed = unsafe { pit::read() };
    // Calculate nanoseconds since last interrupt
    (elapsed as u128 * pit::PERIOD_FS) / 1_000_000
}
