#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IpiKind {
    Wakeup = 0x40,
    Tlb = 0x41,
    Switch = 0x42,
    Pit = 0x43,

    #[cfg(feature = "profiling")]
    Profile = 0x44,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IpiTarget {
    Current = 1,
    All = 2,
    Other = 3,
}

#[cfg(not(feature = "multi_core"))]
#[inline(always)]
pub fn ipi(_kind: IpiKind, _target: IpiTarget) {}

#[cfg(feature = "multi_core")]
#[inline(always)]
pub fn ipi(kind: IpiKind, target: IpiTarget) {
    use crate::device::local_apic::the_local_apic;

    #[cfg(feature = "profiling")]
    if matches!(kind, IpiKind::Profile) {
        let icr = (target as u64) << 18 | 1 << 14 | 0b100 << 8;
        unsafe { the_local_apic().set_icr(icr) };
        return;
    }

    let icr = (target as u64) << 18 | 1 << 14 | (kind as u64);
    unsafe { the_local_apic().set_icr(icr) };
}

#[cfg(feature = "multi_core")]
#[inline(always)]
pub fn ipi_single(kind: IpiKind, target: &crate::percpu::PercpuBlock) {
    use crate::device::local_apic::the_local_apic;

    if let Some(apic_id) = target.misc_arch_info.apic_id_opt.get() {
        unsafe {
            the_local_apic().ipi(apic_id, kind);
        }
    }
}

#[cfg(not(feature = "multi_core"))]
#[inline(always)]
pub fn ipi_single(_kind: IpiKind, _target: &crate::percpu::PercpuBlock) {}
