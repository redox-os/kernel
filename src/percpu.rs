use crate::LogicalCpuId;
use crate::context::switch::ContextSwitchPercpu;
use crate::profiling::RingBuffer;

/// The percpu block, that stored all percpu variables.
pub struct PercpuBlock {
    /// A unique immutable number that identifies the current CPU - used for scheduling
    pub cpu_id: LogicalCpuId,

    /// Context management
    pub switch_internals: ContextSwitchPercpu,

    // TODO: Put mailbox queues here, e.g. for TLB shootdown? Just be sure to 128-byte align it
    // first to avoid cache invalidation.

    pub profiling: Option<&'static RingBuffer>,
}

// PercpuBlock::current() is implemented somewhere in the arch-specific modules
