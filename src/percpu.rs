use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::boxed::Box;

use crate::LogicalCpuId;
use crate::context::switch::ContextSwitchPercpu;

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

const N: usize = 64 * 1024 * 1024;

pub struct RingBuffer {
    head: AtomicUsize,
    tail: AtomicUsize,
    buf: &'static [UnsafeCell<usize>; N],
    pub(crate) nmi_kcount: AtomicUsize,
    pub(crate) nmi_ucount: AtomicUsize,
}

impl RingBuffer {
    unsafe fn advance_head(&self, n: usize) {
        self.head.store(self.head.load(Ordering::Acquire).wrapping_add(n), Ordering::Release);
    }
    unsafe fn advance_tail(&self, n: usize) {
        self.tail.store(self.tail.load(Ordering::Acquire).wrapping_add(n), Ordering::Release);
    }
    unsafe fn sender_owned(&self) -> [&[UnsafeCell<usize>]; 2] {
        let head = self.head.load(Ordering::Acquire) % N;
        let tail = self.tail.load(Ordering::Acquire) % N;

        if head <= tail {
            [&self.buf[tail..], &self.buf[..head]]
        } else {
            [&self.buf[tail..head], &[]]
        }
    }
    unsafe fn receiver_owned(&self) -> [&[UnsafeCell<usize>]; 2] {
        let head = self.head.load(Ordering::Acquire) % N;
        let tail = self.tail.load(Ordering::Acquire) % N;

        if head > tail {
            [&self.buf[head..], &self.buf[..tail]]
        } else {
            [&self.buf[head..tail], &[]]
        }
    }
    pub unsafe fn extend(&self, mut slice: &[usize]) -> usize {
        let mut n = 0;
        for mut sender_slice in self.sender_owned() {
            while !slice.is_empty() && !sender_slice.is_empty() {
                sender_slice[0].get().write(slice[0]);
                slice = &slice[1..];
                sender_slice = &sender_slice[1..];
                n += 1;
            }
        }
        self.advance_tail(n);
        n
    }
    pub unsafe fn peek(&self) -> [&[usize]; 2] {
        self.receiver_owned().map(|slice| core::slice::from_raw_parts(slice.as_ptr().cast(), slice.len()))
    }
    pub unsafe fn advance(&self, n: usize) {
        self.advance_head(n)
    }
    pub fn create() -> &'static Self {

        Box::leak(Box::new(Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buf: Box::leak(unsafe { Box::new_zeroed().assume_init() }),
            nmi_kcount: AtomicUsize::new(0),
            nmi_ucount: AtomicUsize::new(0),
        }))
    }
}

// PercpuBlock::current() is implemented somewhere in the arch-specific modules
