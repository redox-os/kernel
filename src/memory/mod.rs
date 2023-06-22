//! # Memory management
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/allocating-frames.html)

use core::cmp;
use core::num::NonZeroUsize;
use core::ops::Deref;
use core::sync::atomic::AtomicUsize;

use crate::arch::rmm::LockedAllocator;
use crate::common::try_box_slice_new;
pub use crate::paging::{PAGE_SIZE, PhysicalAddress};
use crate::rmm::areas;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rmm::{
    FrameAllocator,
    FrameCount,
};
use spin::RwLock;
use crate::syscall::flag::{PartialAllocStrategy, PhysallocFlags};
use crate::syscall::error::{ENOMEM, Error};

/// A memory map area
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
pub struct MemoryArea {
    pub base_addr: u64,
    pub length: u64,
    pub _type: u32,
    pub acpi: u32
}

/// Get the number of frames available
pub fn free_frames() -> usize {
    unsafe {
        LockedAllocator.usage().free().data()
    }
}

/// Get the number of frames used
pub fn used_frames() -> usize {
    unsafe {
        LockedAllocator.usage().used().data()
    }
}

/// Allocate a range of frames
pub fn allocate_frames(count: usize) -> Option<Frame> {
    unsafe {
        LockedAllocator.allocate(FrameCount::new(count)).map(|phys| {
            Frame::containing_address(PhysicalAddress::new(phys.data()))
        })
    }
}
pub fn allocate_frames_complex(count: usize, flags: PhysallocFlags, strategy: Option<PartialAllocStrategy>, min: usize) -> Option<(Frame, usize)> {
    //TODO: support partial allocation
    if flags == PhysallocFlags::SPACE_64 && strategy.is_none() {
        let actual = cmp::max(count, min);
        return allocate_frames(actual).map(|frame| (frame, actual));
    }

    println!(
        "!!!! allocate_frames_complex not implemented for count {}, flags {:?}, strategy {:?}, min {}",
        count,
        flags,
        strategy,
        min
    );
    None
}

/// Deallocate a range of frames frame
// TODO: Make unsafe
pub fn deallocate_frames(frame: Frame, count: usize) {
    unsafe {
        LockedAllocator.free(
            rmm::PhysicalAddress::new(frame.start_address().data()),
            FrameCount::new(count)
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Frame {
    // TODO: NonZeroUsize
    //
    // On x86/x86_64, all memory below 1 MiB is reserved, and although some frames in that range
    // may end up in the paging code, it's very unlikely that frame 0x0 would.
    number: NonZeroUsize,
}
impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[frame at {:p}]", self.start_address().data() as *const u8)
    }
}

impl Frame {
    /// Get the address of this frame
    pub fn start_address(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.number.get() * PAGE_SIZE)
    }

    //TODO: Set private
    pub fn clone(&self) -> Frame {
        Frame {
            number: self.number
        }
    }

    /// Create a frame containing `address`
    pub fn containing_address(address: PhysicalAddress) -> Frame {
        Frame {
            number: NonZeroUsize::new(address.data() / PAGE_SIZE).expect("frame 0x0 is reserved"),
        }
    }

    //TODO: Set private
    pub fn range_inclusive(start: Frame, end: Frame) -> FrameIter {
        FrameIter { start, end }
    }
    pub fn next_by(self, n: usize) -> Self {
        Self {
            number: self.number.get().checked_add(n).and_then(NonZeroUsize::new).expect("overflow in Frame::next_by"),
        }
    }
    pub fn offset_from(self, from: Self) -> usize {
        from.number.get().checked_sub(self.number.get()).expect("overflow in Frame::offset_from")
    }
}

pub struct FrameIter {
    start: Frame,
    end: Frame,
}

impl Iterator for FrameIter {
    type Item = Frame;

    fn next(&mut self) -> Option<Frame> {
        if self.start <= self.end {
            let frame = self.start.clone();
            self.start = self.start.next_by(1);
            Some(frame)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct Enomem;

impl From<Enomem> for Error {
    fn from(_: Enomem) -> Self {
        Self::new(ENOMEM)
    }
}

#[derive(Debug)]
pub struct RaiiFrame {
    inner: Frame,
}
impl RaiiFrame {
    // TODO: Unsafe?
    pub fn new(frame: Frame) -> Self {
        Self {
            inner: frame,
        }
    }
    pub fn allocate() -> Result<Self, Enomem> {
        allocate_frames(1).map(Self::new).ok_or(Enomem)
    }
    pub fn get(&self) -> Frame {
        self.inner
    }
    pub fn take_ownership(self) -> Frame {
        let frame = self.inner.clone();
        core::mem::forget(self);
        frame
    }
}

impl Drop for RaiiFrame {
    fn drop(&mut self) {
        crate::memory::deallocate_frames(self.inner, 1);
    }
}

pub struct PageInfo {
    refcount: AtomicUsize,
    cow_refcount: AtomicUsize,
    flags: FrameFlags,
    _padding: usize,
}
bitflags::bitflags! {
    struct FrameFlags: usize {
        const NONE = 0;
    }
}

// TODO: Very read-heavy RwLock?
pub static SECTIONS: RwLock<Box<[&'static Section]>> = RwLock::new(Box::new([]));

pub struct Section {
    base: Frame,
    frames: Box<[PageInfo]>,
}

pub const MAX_SECTION_SIZE_BITS: u32 = 27;
pub const MAX_SECTION_SIZE: usize = 1 << MAX_SECTION_SIZE_BITS;
pub const MAX_SECTION_PAGE_COUNT: usize = MAX_SECTION_SIZE / PAGE_SIZE;

#[cold]
pub fn init_mm() {
    let mut guard = SECTIONS.write();
    let mut sections = Vec::new();

    for memory_map_area in areas().iter().filter(|area| area.size > 0) {
        let mut pages_left = memory_map_area.size.div_floor(PAGE_SIZE);
        let mut base = Frame::containing_address(memory_map_area.base);

        while pages_left > 0 {
            let section_page_count = core::cmp::min(pages_left, MAX_SECTION_PAGE_COUNT);

            sections.push(Box::leak(Box::new(Section {
                base,
                // TODO: zeroed?
                frames: try_box_slice_new(PageInfo::new, section_page_count).expect("failed to allocate pages array"),
            })) as &'static Section);

            pages_left -= section_page_count;
            base = base.next_by(section_page_count);
        }
    }

    sections.sort_unstable_by_key(|s| s.base);

    *guard = sections.into_boxed_slice();
}
impl PageInfo {
    pub fn new() -> Self {
        Self {
            refcount: AtomicUsize::new(0),
            cow_refcount: AtomicUsize::new(0),
            flags: FrameFlags::NONE,
            _padding: 0,
        }
    }
}
pub fn get_page(frame: Frame) -> Option<&'static PageInfo> {
    let sections = SECTIONS.read();

    let idx = sections
        .binary_search_by_key(&frame, |section| section.base)
        .unwrap_or_else(|e| e);

    let section = sections.get(idx)?;

    section.frames.get(frame.offset_from(section.base))

    /*
    sections
        .range(..=frame)
        .next_back()
        .filter(|(base, section)| frame <= base.next_by(section.frames.len()))
        .map(|(base, section)| PageInfoHandle { section, idx: frame.offset_from(*base) })
    */
}
