//! # Memory management
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/allocating-frames.html)

use core::cmp;
use core::num::NonZeroUsize;

use crate::arch::rmm::LockedAllocator;
use crate::common::try_box_slice_new;
use crate::context::memory::init_frame;
pub use crate::paging::{PAGE_SIZE, PhysicalAddress};
use crate::rmm::areas;

use alloc::boxed::Box;
use alloc::vec::Vec;
use rmm::{
    FrameAllocator,
    FrameCount,
};
use spin::{RwLock, Mutex};
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

    log::error!(
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
        // TODO: Use special tag?
        init_frame(RefCount::One).map_err(|_| Enomem).map(|inner| Self { inner })
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
        get_page_info(self.inner).expect("RaiiFrame lacking PageInfo").lock().refcount = 0;
        crate::memory::deallocate_frames(self.inner, 1);
    }
}

// TODO: Make PageInfo a union, since *every* allocated page will have an associated PageInfo.
// Pages that aren't AddrSpace data pages, such as paging-structure pages, might use the memory
// occupied by a PageInfo for something else, potentially allowing paging structure-level CoW too.
//
// TODO: Another interesting possibility would be to use a slab allocator for (ideally
// power-of-two) allocations smaller than a page, in which case this PageInfo might store a bitmap
// of used sub-allocations.
//
// TODO: Alternatively or in conjunction, the PageInfo can store the number of used entries for
// each page table, possibly even recursively (total number of mapped pages).
#[derive(Debug)]
pub struct PageInfo {
    /// Stores the reference count to this page, i.e. the number of present page table entries that
    /// point to this particular frame.
    ///
    /// Bits 0..=N-1 are used for the actual reference count, whereas bit N-1 indicates the page is
    /// shared if set, and CoW if unset. The flag is not meaningful when the refcount is 0 or 1.
    pub refcount: usize,

    // TODO: AtomicFlags?
    pub flags: FrameFlags,
}
const RC_SHARED_NOT_COW: usize = 1 << (usize::BITS - 1);

// TODO: Use some of the flag bits as a tag, indicating the type of page (e.g. paging structure,
// userspace data page, or kernel heap page). This could be done only when debug assertions are
// enabled.
bitflags::bitflags! {
    pub struct FrameFlags: usize {
        const NONE = 0;
    }
}

// TODO: Very read-heavy RwLock?
//
// XXX: Is it possible to safely initialize an empty boxed slice from a const context?
//pub static SECTIONS: RwLock<Box<[&'static Section]>> = RwLock::new(Box::new([]));
pub static SECTIONS: RwLock<Vec<&'static Section>> = RwLock::new(Vec::new());

pub struct Section {
    base: Frame,
    frames: Box<[Mutex<PageInfo>]>,
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
                // TODO: zeroed rather than PageInfo::new()?
                frames: try_box_slice_new(|| Mutex::new(PageInfo::new()), section_page_count).expect("failed to allocate pages array"),
            })) as &'static Section);

            pages_left -= section_page_count;
            base = base.next_by(section_page_count);
        }
    }

    sections.sort_unstable_by_key(|s| s.base);
    sections.shrink_to_fit();

    *guard = sections;
}
#[derive(Debug)]
pub enum AddRefError {
    RcOverflow,
    CowToShared,
    SharedToCow,
}
impl PageInfo {
    pub fn new() -> Self {
        Self {
            refcount: 0,
            flags: FrameFlags::NONE,
        }
    }
    pub fn add_ref(&mut self, kind: RefKind) -> Result<(), AddRefError> {
        let old = self.refcount();
        match (self.refcount(), kind) {
            (RefCount::Zero, _) => self.refcount = 1,
            (RefCount::One, RefKind::Cow) => self.refcount = 2,
            (RefCount::One, RefKind::Shared) => self.refcount = 2 | RC_SHARED_NOT_COW,
            (RefCount::Cow(prev), RefKind::Cow) => self.refcount = prev.get().checked_add(1).ok_or(AddRefError::RcOverflow)?,
            (RefCount::Shared(prev), RefKind::Shared) => self.refcount = prev.get().checked_add(1).ok_or(AddRefError::RcOverflow)? | RC_SHARED_NOT_COW,
            (RefCount::Cow(prev), RefKind::Shared) => return Err(AddRefError::CowToShared),
            (RefCount::Shared(prev), RefKind::Cow) => return Err(AddRefError::SharedToCow),
        }
        Ok(())
    }
    #[must_use = "must deallocate if refcount reaches zero"]
    pub fn remove_ref(&mut self) -> RefCount {
        let old = self.refcount();

        match self.refcount() {
            RefCount::Zero => panic!("refcount was already zero when calling remove_ref!"),
            RefCount::One => self.refcount = 0,
            RefCount::Cow(prev) => self.refcount -= 1,
            RefCount::Shared(prev) => {
                self.refcount = prev.get() - 1;

                if self.refcount > 1 {
                    self.refcount |= RC_SHARED_NOT_COW;
                }
            }
        }

        self.refcount()
    }
    pub fn allows_writable(&self) -> bool {
        match self.refcount() {
            RefCount::Zero | RefCount::One => true,
            RefCount::Cow(_) => false,
            RefCount::Shared(_) => true,
        }
    }

    pub fn refcount(&self) -> RefCount {
        if let Some(nz_refcount) = NonZeroUsize::new(self.refcount) {
            if self.refcount == 1 {
                RefCount::One
            } else if self.refcount & RC_SHARED_NOT_COW == RC_SHARED_NOT_COW {
                RefCount::Shared(NonZeroUsize::new(self.refcount & !RC_SHARED_NOT_COW).unwrap())
            } else {
                RefCount::Cow(nz_refcount)
            }
        } else {
            RefCount::Zero
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum RefKind {
    Cow,
    Shared,
    // TODO: Observer?
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RefCount {
    Zero,
    One,
    Shared(NonZeroUsize),
    Cow(NonZeroUsize),
}
impl RefCount {
    pub fn to_raw(self) -> usize {
        match self {
            Self::Zero => 0,
            Self::One => 1,
            Self::Shared(inner) => inner.get() | RC_SHARED_NOT_COW,
            Self::Cow(inner) => inner.get(),
        }
    }
}
pub fn get_page_info(frame: Frame) -> Option<&'static Mutex<PageInfo>> {
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
