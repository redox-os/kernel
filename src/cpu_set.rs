use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::string::{String, ToString};

/// A unique number used internally by the kernel to identify CPUs.
///
/// This is usually but not necessarily the same as the APIC ID.

// TODO: Differentiate between logical CPU IDs and hardware CPU IDs (e.g. APIC IDs)
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
// TODO: NonMaxUsize?
// TODO: Optimize away this type if not cfg!(feature = "multi_core")
pub struct LogicalCpuId(u32);

impl LogicalCpuId {
    pub const BSP: Self = Self::new(0);

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

#[cfg(target_pointer_width = "64")]
pub const MAX_CPU_COUNT: u32 = 128;

#[cfg(target_pointer_width = "32")]
pub const MAX_CPU_COUNT: u32 = 32;

const SET_WORDS: usize = (MAX_CPU_COUNT / usize::BITS) as usize;

// TODO: Support more than 128 CPUs.
// The maximum number of CPUs on Linux is configurable, and the type for LogicalCpuSet and
// LogicalCpuId may be optimized accordingly. In that case, box the mask if it's larger than some
// base size (probably 256 bytes).
#[derive(Debug)]
pub struct LogicalCpuSet([AtomicUsize; SET_WORDS]);

fn parts(id: LogicalCpuId) -> (usize, u32) {
    ((id.get() / usize::BITS) as usize, id.get() % usize::BITS)
}
impl LogicalCpuSet {
    pub const fn empty() -> Self {
        const ZEROES: AtomicUsize = AtomicUsize::new(0);
        Self([ZEROES; SET_WORDS])
    }
    pub const fn all() -> Self {
        const ONES: AtomicUsize = AtomicUsize::new(!0);
        Self([ONES; SET_WORDS])
    }
    pub fn contains(&mut self, id: LogicalCpuId) -> bool {
        let (word, bit) = parts(id);
        *self.0[word].get_mut() & (1 << bit) != 0
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

    pub fn iter_mut(&mut self) -> impl Iterator<Item = LogicalCpuId> + '_ {
        // TODO: Will this be optimized away?
        self.0.iter_mut().enumerate().flat_map(move |(i, w)| {
            (0..usize::BITS).filter_map(move |b| {
                if *w.get_mut() & 1 << b != 0 {
                    Some(LogicalCpuId::new(i as u32 * usize::BITS + b))
                } else {
                    None
                }
            })
        })
    }
}

impl ToString for LogicalCpuSet {
    fn to_string(&self) -> String {
        use core::fmt::Write;

        let cpu_count = crate::cpu_count();

        let mut ret = String::new();
        let raw = self.to_raw();
        let words = raw.get(..(cpu_count / usize::BITS) as usize).unwrap_or(&[]);
        for (i, word) in words.iter().enumerate() {
            if i != 0 {
                write!(ret, "_").unwrap();
            }
            let word = if i == words.len() - 1 {
                *word & ((1_usize << (cpu_count % usize::BITS)) - 1)
            } else {
                *word
            };
            write!(ret, "{word:x}").unwrap();
        }
        ret
    }
}

pub type RawMask = [usize; SET_WORDS];

pub fn mask_as_bytes(mask: &RawMask) -> &[u8] {
    unsafe { core::slice::from_raw_parts(mask.as_ptr().cast(), core::mem::size_of::<RawMask>()) }
}
