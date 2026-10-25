use core::{
    array,
    fmt::Display,
    sync::atomic::{AtomicUsize, Ordering},
};

use syscall::CpuSet;

use crate::CPU_COUNT;

/// A unique number used internally by the kernel to identify CPUs.
///
/// This is usually but not necessarily the same as the APIC ID.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
// TODO: NonMaxUsize?
// TODO: Optimize away this type if not cfg!(feature = "multi_core")
pub struct LogicalCpuId(u32);

impl LogicalCpuId {
    pub const BSP: Self = Self::new(0);

    pub fn next() -> Self {
        let id = CPU_COUNT.fetch_add(1, Ordering::Relaxed);
        assert!(id < MAX_CPU_COUNT);
        Self(id)
    }

    pub const fn new(inner: u32) -> Self {
        Self(inner)
    }
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl core::fmt::Debug for LogicalCpuId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[logical cpu #{}]", self.0)
    }
}
impl core::fmt::Display for LogicalCpuId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

use syscall::CPU_SET_WORDS;
pub use syscall::MAX_CPU_COUNT;

// TODO: Support more than 128 CPUs.
// The maximum number of CPUs on Linux is configurable, and the type for LogicalCpuSet and
// LogicalCpuId may be optimized accordingly. In that case, box the mask if it's larger than some
// base size (probably 256 bytes).
#[derive(Debug)]
pub struct LogicalCpuSet([AtomicUsize; CPU_SET_WORDS]);

fn parts(id: LogicalCpuId) -> (usize, u32) {
    ((id.get() / usize::BITS) as usize, id.get() % usize::BITS)
}
impl LogicalCpuSet {
    pub const fn empty() -> Self {
        Self([const { AtomicUsize::new(0) }; CPU_SET_WORDS])
    }

    pub const fn all() -> Self {
        Self([const { AtomicUsize::new(!0) }; CPU_SET_WORDS])
    }

    pub fn contains(&self, id: LogicalCpuId) -> bool {
        let (word, bit) = parts(id);
        self.0[word].load(Ordering::Acquire) & (1 << bit) != 0
    }

    pub fn atomic_set(&self, id: LogicalCpuId) {
        let (word, bit) = parts(id);
        let _ = self.0[word].fetch_or(1 << bit, Ordering::Release);
    }

    pub fn atomic_clear(&self, id: LogicalCpuId) {
        let (word, bit) = parts(id);
        let _ = self.0[word].fetch_and(!(1 << bit), Ordering::Release);
    }

    pub fn override_from(&mut self, raw: &RawMask) {
        self.0 = raw.map(AtomicUsize::new);
    }

    pub fn to_raw(&self) -> RawMask {
        self.0.each_ref().map(|w| w.load(Ordering::Acquire))
    }

    pub fn iter(&self) -> impl Iterator<Item = LogicalCpuId> + '_ {
        self.0.iter().enumerate().flat_map(move |(i, w)| {
            (0..usize::BITS).filter_map(move |b| {
                if w.load(Ordering::Acquire) & (1 << b) != 0 {
                    Some(LogicalCpuId::new(i as u32 * usize::BITS + b))
                } else {
                    None
                }
            })
        })
    }
}

impl Display for LogicalCpuSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let cpu_count = crate::cpu_count();

        let raw = self.to_raw();
        let words = raw
            .get(..cpu_count.div_ceil(usize::BITS) as usize)
            .unwrap_or(&[]);
        for (i, word) in words.iter().enumerate() {
            if i != 0 {
                write!(f, "_")?;
            }
            let word = if i == words.len() - 1 {
                *word & ((1_usize << (cpu_count % usize::BITS)) - 1)
            } else {
                *word
            };
            write!(f, "{word:X}")?;
        }
        Ok(())
    }
}

pub type RawMask = [usize; CPU_SET_WORDS];

impl From<CpuSet> for LogicalCpuSet {
    fn from(value: CpuSet) -> Self {
        LogicalCpuSet(value.raw().map(|e| AtomicUsize::new(e)))
    }
}
