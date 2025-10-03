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

#[inline(always)]
pub fn ipi(_kind: IpiKind, _target: IpiTarget) {
    if cfg!(not(feature = "multi_core")) {
        return;
    }

    // FIXME implement
}

#[inline(always)]
pub fn ipi_single(_kind: IpiKind, _target: &crate::percpu::PercpuBlock) {
    if cfg!(not(feature = "multi_core")) {
        return;
    }

    // FIXME implement
}
