#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IpiKind {
    Wakeup = 0x40,
    Tlb = 0x41,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum IpiTarget {
    Other = 3,
}

#[cfg(not(feature = "multi_core"))]
#[inline(always)]
pub fn ipi(_kind: IpiKind, _target: IpiTarget) {}

#[cfg(feature = "multi_core")]
#[inline(always)]
pub fn ipi(_kind: IpiKind, _target: IpiTarget) {}

#[cfg(not(feature = "multi_core"))]
#[inline(always)]
pub fn ipi_single(_kind: IpiKind, _target: crate::cpu_set::LogicalCpuId) {}

#[cfg(feature = "multi_core")]
#[inline(always)]
pub fn ipi_single(_kind: IpiKind, _target: crate::cpu_set::LogicalCpuId) {}
