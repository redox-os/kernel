#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IpiKind {
    Wakeup = 0x40,
    Tlb = 0x41,
    Switch = 0x42,
    Pit = 0x43,
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
    use crate::device::local_apic::LOCAL_APIC;

    let icr = (target as u64) << 18 | 1 << 14 | (kind as u64);
    unsafe { LOCAL_APIC.set_icr(icr) };
}
