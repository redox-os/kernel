use crate::context::switch::ContextSwitchPercpu;

/// The percpu block, that stored all percpu variables.
pub struct PercpuBlock {
    /// A unique immutable number that identifies the current CPU - used for scheduling
    // TODO: Differentiate between logical CPU IDs and hardware CPU IDs (e.g. APIC IDs)
    pub cpu_id: usize,

    /// Context management
    pub switch_internals: ContextSwitchPercpu,

    // TODO: Put mailbox queues here, e.g. for TLB shootdown? Just be sure to 128-byte align it
    // first to avoid cache invalidation.
}

// PercpuBlock::current() is implemented somewhere in the arch-specific modules
