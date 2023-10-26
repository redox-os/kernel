//! # Memory management
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/allocating-frames.html)

use core::{
    cell::SyncUnsafeCell,
    mem,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};

use spin::Mutex;

use crate::context::{self, memory::{AccessMode, PfError}};
use crate::kernel_executable_offsets::{__usercopy_start, __usercopy_end};
use crate::paging::Page;
pub use crate::paging::{PAGE_SIZE, PAGE_MASK, PhysicalAddress, RmmA, RmmArch};
use rmm::{
    FrameAllocator,
    FrameCount, VirtualAddress, TableKind, BumpAllocator,
};
use crate::syscall::error::{ENOMEM, Error};

/// A memory map area
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
pub struct MemoryArea {
    pub base_addr: u64,
    pub length: u64,
    pub _type: u32,
    pub acpi: u32,
}

/// Get the number of frames available
pub fn free_frames() -> usize {
    0
}

/// Get the number of frames used
pub fn used_frames() -> usize {
    0
}

/// Allocate a range of frames
pub fn allocate_frames(count: usize) -> Option<Frame> {
    allocate_frames_complex(count, (), None, count).map(|(f, _)| f)
}
pub fn allocate_frame() -> Option<Frame> {
    allocate_frames(1)
}
pub fn allocate_frames_complex(count: usize, flags: (), strategy: Option<()>, min: usize) -> Option<(Frame, usize)> {
    // TODO: Split into sub-power of two allocations.
    let min_order = min.next_power_of_two().trailing_zeros();
    let _req_order = count.next_power_of_two().trailing_zeros();

    let mut freelist = FREELIST.lock();

    let Some((frame_order, frame)) = freelist[min_order as usize..].iter().enumerate().find_map(|(i, f)| f.map(|f| (i, f))) else {
        // TODO: For larger sizes than the max order, split into power of two allocations.
        log::error!("COUNT {min}");
        log::error!("FREELIST {freelist:#?}");
        log::error!(":(");
        return None;
    };

    let info = get_page_info(frame)
        .unwrap_or_else(|| panic!("no page info for allocated frame {frame:?}"))
        .as_free().expect("freelist frames must not be marked used!");
    let next_free = info.next();
    //log::info!("FREE {frame:?} ORDER {frame_order} NEXT_FREE {next_free:?}");

    freelist[frame_order] = next_free.frame();

    // TODO: Is this LIFO cache optimal?
    for order in (min..frame_order).rev() {
        let order_page_count = 1 << (order - 1);

        let hi = frame.next_by(order_page_count);
        //log::info!("SPLIT INTO {frame:?}:{hi:?} ORDER {order}");

        if let Some(old_head) = freelist[order].replace(hi) {
            let hi_info = get_page_info(hi)
                .expect("no page info for allocated frame")
                .as_free().expect("freelist cannot contain used pages!");

            hi_info.set_next(P2Frame::new(Some(old_head), order as u32));

            get_page_info(old_head).expect("freelist head needs page info")
                .as_free().expect("freelist head cannot be in use")
                .set_prev(P2Frame::new(Some(hi), order as u32));
        }
    }

    info.mark_used();

    unsafe {
        (RmmA::phys_to_virt(frame.start_address()).data() as *mut u8).write_bytes(0, PAGE_SIZE << min_order);
    }

    //log::info!("ALLOCATED {frame:?}+2^{min_order}");
    /*unsafe {
        let mut found = false;
        for area in AREAS {
            if frame.start_address() >= area.base && frame.next_by(1 << min_order).start_address() < area.base.add(area.size) {
                found = true;
                break;
            }
        }
        assert!(found);
    }*/
    Some((frame, PAGE_SIZE << min_order))
}

/// Deallocate a range of frames
pub unsafe fn deallocate_frames(frame: Frame, count: usize) {
    let max_order = core::cmp::min(MAX_ORDER, count.next_power_of_two().trailing_zeros());

    let (first_aligned, chunk_order, number_of_chunks) = (0..=max_order).rev().find_map(|order| {
        let bytes_for_order = PAGE_SIZE << order;
        let first_aligned = frame.start_address().data().next_multiple_of(bytes_for_order);
        let last_aligned = (frame.start_address().data() + count * PAGE_SIZE) / bytes_for_order * bytes_for_order;
        let chunks = (last_aligned - first_aligned) / bytes_for_order;

        (first_aligned < last_aligned).then_some((first_aligned, order, chunks))
    }).expect("must succeed at least for order=0");

    for i in 0..number_of_chunks {
        deallocate_p2frame(Frame::containing_address(PhysicalAddress::new(first_aligned + i * (PAGE_SIZE << chunk_order))), chunk_order);
    }

    let first_aligned_frame = Frame::containing_address(PhysicalAddress::new(first_aligned));
    let lo_subblock_page_count = first_aligned_frame.offset_from(frame);
    let hi_subblock_page_count = count - (number_of_chunks << chunk_order) - lo_subblock_page_count;
    deallocate_frames(frame, lo_subblock_page_count);
    deallocate_frames(first_aligned_frame.next_by(number_of_chunks << chunk_order), hi_subblock_page_count);

    //log::info!("DEALLOCED {frame:?}+{count}");
    loop {}
}

unsafe fn deallocate_p2frame(mut frame: Frame, order: u32) {
    let mut freelist = FREELIST.lock();
    let mut largest_order = 0;

    for merge_order in order..=MAX_ORDER {
        // Because there's a PageInfo, this frame must be allocator-owned. We need to be very
        // careful with who owns this page, as the refcount can be anything from 0 (undefined) to
        // 2^addrwidth - 1. However, allocation and deallocation must be synchronized (the "next"
        // word of the PageInfo).

        let frame_info = get_page_info(frame)
            .expect("deallocating frame without PageInfo")
            .as_free().expect("deallocating used page!");

        let Some(neighbor) = frame.neighbor(merge_order) else {
            break;
        };

        let Some(neighbor_info) = get_page_info(neighbor) else {
            // The frame that was deallocated, was the end of a contiguous allocator memory range.
            break;
        };

        let PageInfoKind::Free(neighbor_info) = neighbor_info.kind() else {
            // The frame is currently in use (refcounted). It cannot be merged!
            break;
        };

        // Whether or not there's a linked frame, the order is nevertheless stored.
        if neighbor_info.next().order() != merge_order {
            break;
        }

        // Link frame->prev->next to neighbor->next
        if let Some(prev_info) = frame_info.prev().frame() {
            get_page_info(prev_info).expect("linked frame lacks PageInfo")
                .as_free().expect("frame->prev pointing to used frame!")
                .set_next(neighbor_info.next())
        }
        // Link neighbor->next->prev to frame->prev
        if let Some(next_info) = neighbor_info.next().frame() {
            get_page_info(next_info).expect("linked frame lacks PageInfo")
                .as_free().expect("neighbor->next pointing to used frame!")
                .set_prev(frame_info.prev())
        }

        // Pick either frame or neighbor depending on which is aligned to the next power of two.
        frame = frame.align_down_to_order(order)
            .expect("must succeed since the neighbor p2frame existed");

        largest_order = merge_order;
    }

    if let Some(old_head) = freelist[largest_order as usize].replace(frame) {
        let head_info = get_page_info(old_head).expect("failed to get page info for old head")
            .as_free().expect("freelist head is currently in use!");

        head_info.set_next(P2Frame::new(Some(frame), largest_order));

        get_page_info(frame).expect("failed to get page info for possibly merged frame")
            .as_free().expect("page was used but should be free")
            .set_prev(P2Frame::new(Some(old_head), largest_order));
    }

    log::info!("FREED {frame:?}+2^{order}");
}

pub unsafe fn deallocate_frame(frame: Frame) {
    deallocate_p2frame(frame, 0)
}

const ORDER_COUNT: u32 = 11;
const MAX_ORDER: u32 = ORDER_COUNT - 1;

pub struct FreeList {
    for_orders: [Option<Frame>; ORDER_COUNT as usize],
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Frame {
    // On x86/x86_64, all memory below 1 MiB is reserved, and although some frames in that range
    // may end up in the paging code, it's very unlikely that frame 0x0 would.
    physaddr: NonZeroUsize,
}

/// Option<Frame> combined with power-of-two size.
#[derive(Clone, Copy)]
struct P2Frame(usize);
impl P2Frame {
    fn new(frame: Option<Frame>, order: u32) -> Self {
        Self(
            frame.map_or(0, |f| f.physaddr.get()) | (order as usize),
        )
    }
    fn get(self) -> (Option<Frame>, u32) {
        let page_off_mask = PAGE_SIZE - 1;
        (NonZeroUsize::new(self.0 & !page_off_mask).map(|physaddr| Frame { physaddr }), (self.0 & page_off_mask) as u32)
    }
    fn frame(self) -> Option<Frame> {
        self.get().0
    }
    fn order(self) -> u32 {
        self.get().1
    }
}
impl core::fmt::Debug for P2Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (frame, order) = self.get();
        write!(f, "[frame at {frame:?}] order {order}")
    }
}

impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "[frame at {:p}]",
            self.start_address().data() as *const u8
        )
    }
}

impl Frame {
    /// Get the address of this frame
    // TODO: Remove
    pub fn start_address(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.physaddr.get())
    }

    /// Create a frame containing `address`
    pub fn containing(address: PhysicalAddress) -> Frame {
        Frame {
            physaddr: NonZeroUsize::new(address.data() & !PAGE_MASK).expect("frame 0x0 is reserved"),
        }
    }
    // TODO: Remove
    pub fn containing_address(address: PhysicalAddress) -> Frame {
        Self::containing(address)
    }
    pub fn base(self) -> PhysicalAddress {
        PhysicalAddress::new(self.physaddr.get())
    }

    //TODO: Set private
    pub fn range_inclusive(start: Frame, end: Frame) -> impl Iterator<Item = Frame> {
        (start.physaddr.get()..=end.physaddr.get()).step_by(PAGE_SIZE).map(|number| Frame { physaddr: NonZeroUsize::new(number).unwrap() })
    }
    pub fn next_by(self, n: usize) -> Self {
        Self {
            physaddr: self
                .physaddr
                .get()
                .checked_add(n * PAGE_SIZE)
                .and_then(NonZeroUsize::new)
                .expect("overflow in Frame::next_by"),
        }
    }
    pub fn prev_by(self, n: usize) -> Self {
        Self {
            physaddr: self.physaddr.get().checked_sub(n.checked_mul(PAGE_SIZE).expect("unreasonable n")).and_then(NonZeroUsize::new).expect("overflow in Frame::prev_by"),
        }
    }
    pub fn neighbor(self, order: u32) -> Option<Self> {
        if self.is_aligned_to_order(order) {
            Some(self.next_by(1 << order))
        } else {
            self.align_down_to_order(order)
        }
    }
    pub fn align_down_to_order(self, order: u32) -> Option<Self> {
        Some(Self { physaddr: NonZeroUsize::new(self.physaddr.get() / (PAGE_SIZE << order) * (PAGE_SIZE << order))? })
    }
    pub fn offset_from(self, from: Self) -> usize {
        self.physaddr
            .get()
            .checked_sub(from.physaddr.get())
            .expect("overflow in Frame::offset_from") / PAGE_SIZE
    }
    pub fn is_aligned_to_order(self, order: u32) -> bool {
        self.start_address().data() % (PAGE_SIZE << order) == 0
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
    pub fn allocate() -> Result<Self, Enomem> {
        init_frame(RefCount::One)
            .map_err(|_| Enomem)
            .map(|inner| Self { inner })
    }
    pub fn get(&self) -> Frame {
        self.inner
    }
}

impl Drop for RaiiFrame {
    fn drop(&mut self) {
        if get_page_info(self.inner)
            .expect("RaiiFrame lacking PageInfo")
            .remove_ref()
            == RefCount::Zero
        {
            unsafe {
                crate::memory::deallocate_frames(self.inner, 1);
            }
        }
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
// NOTE: init_sections depends on the default initialized value consisting of all zero bytes.
#[derive(Debug)]
pub struct PageInfo {
    /// Stores the reference count to this page, i.e. the number of present page table entries that
    /// point to this particular frame.
    ///
    /// Bits 0..=N-1 are used for the actual reference count, whereas bit N-1 indicates the page is
    /// shared if set, and CoW if unset. The flag is not meaningful when the refcount is 0 or 1.
    pub refcount: AtomicUsize,

    // TODO: Add one flag indicating whether the page contents is zeroed? Or should this primarily
    // be managed by the memory allocator first?
    pub next: AtomicUsize,
}

enum PageInfoKind<'info> {
    Used(PageInfoUsed<'info>),
    Free(PageInfoFree<'info>),
}
struct PageInfoUsed<'info> {
    refcount: &'info AtomicUsize,
    _misc: &'info AtomicUsize,
}
struct PageInfoFree<'info> {
    prev: &'info AtomicUsize,
    next: &'info AtomicUsize,
    last_next: usize,
}

// There should be at least 2 bits available; even with a 4k page size on a 32-bit system (where a
// paging structure node is itself a 4k page size, i.e. on i386 with 1024 32-bit entries), there
// simply cannot be more than 2^30 entries pointing to the same page. However, to be able to use
// fetch_add safely, we reserve another bit (which makes fetch_add safe if properly reverted, and
// there aren't more than 2^(BITS-2) CPUs on the system).

// Indicates whether the page is free (and thus managed by the allocator), or owned (and thus
// managed by the kernel heap, or most commonly, the virtual memory system). The refcount may
// increase or decrease with fetch_add, but must never flip this bit.
const RC_USED_NOT_FREE: usize = 1 << (usize::BITS - 1);

// Only valid if RC_USED. Controls whether the page is CoW (map readonly, on page fault, copy and
// remap writable) or shared (mapped writable in the first place).
const RC_SHARED_NOT_COW: usize = 1 << (usize::BITS - 2);

// The page refcount limit. This acts as a buffer zone allowing subsequent fetch_sub to correct
// overflow, which works as long as there's fewer CPUs than RC_MAX itself (and interrupts are
// disabled).
const RC_MAX: usize = 1 << (usize::BITS - 3);

const RC_COUNT_MASK: usize = !(RC_USED_NOT_FREE | RC_SHARED_NOT_COW);

// TODO: Use some of the flag bits as a tag, indicating the type of page (e.g. paging structure,
// userspace data page, or kernel heap page). This could be done only when debug assertions are
// enabled.
bitflags::bitflags! {
    #[derive(Debug)]
    pub struct FrameFlags: usize {
        const NONE = 0;
    }
}

static mut ALLOCATOR_DATA: AllocatorData = AllocatorData { sections: &[] };

struct AllocatorData {
    // TODO: Memory hotplugging?
    sections: &'static [Section],
}
static FREELIST: Mutex<[Option<Frame>; ORDER_COUNT as usize]> = Mutex::new([None; ORDER_COUNT as usize]);

pub struct Section {
    base: Frame,
    frames: &'static [PageInfo],
}

pub const MAX_SECTION_SIZE_BITS: u32 = 27;
pub const MAX_SECTION_SIZE: usize = 1 << MAX_SECTION_SIZE_BITS;
pub const MAX_SECTION_PAGE_COUNT: usize = MAX_SECTION_SIZE / PAGE_SIZE;

const _: () = {
    assert!(mem::size_of::<PageInfo>().is_power_of_two());
};

#[cold]
fn init_sections(mut allocator: BumpAllocator<RmmA>) {
    let (free_areas, offset_into_first_free_area) = allocator.free_areas();

    let free_areas_iter = || free_areas.iter().copied().enumerate().map(|(i, area)| if i == 0 {
        rmm::MemoryArea {
            base: area.base.add(offset_into_first_free_area),
            size: area.size - offset_into_first_free_area,
        }
    } else {
        area
    });

    let sections: &'static mut [Section] = {
        let max_section_count: usize = free_areas_iter().map(|area| {
            let aligned_end = area.base.add(area.size).data().next_multiple_of(MAX_SECTION_SIZE);
            let aligned_start = area.base.data() / MAX_SECTION_SIZE * MAX_SECTION_SIZE;

            (aligned_end - aligned_start) / MAX_SECTION_SIZE
        }).sum();
        let section_array_page_count = (max_section_count * mem::size_of::<Section>()).div_ceil(PAGE_SIZE);

        unsafe {
            let base = allocator.allocate(FrameCount::new(section_array_page_count)).expect("failed to allocate sections array");
            core::slice::from_raw_parts_mut(RmmA::phys_to_virt(base).data() as *mut Section, max_section_count)
        }
    };
    log::info!("SECTIONS AT {sections:p}");

    let mut iter = free_areas_iter().peekable();

    let mut i = 0;

    while let Some(mut memory_map_area) = iter.next() {
        // TODO: NonZeroUsize
        assert_ne!(
            memory_map_area.size, 0,
            "RMM should enforce areas are not zeroed"
        );

        // TODO: Would it make sense to naturally align the sections?
        // TODO: Should RMM do this?

        while let Some(next_area) = iter.peek() && next_area.base == memory_map_area.base.add(memory_map_area.size) {
            memory_map_area.size += next_area.size;
            let _ = iter.next();
        }

        assert_eq!(
            memory_map_area.base.data() % PAGE_SIZE,
            0,
            "RMM should enforce area alignment"
        );
        assert_eq!(
            memory_map_area.size % PAGE_SIZE,
            0,
            "RMM should enforce area length alignment"
        );

        let mut pages_left = memory_map_area.size.div_floor(PAGE_SIZE);
        let mut base = Frame::containing_address(memory_map_area.base);

        while pages_left > 0 {
            let page_info_max_count = core::cmp::min(pages_left, MAX_SECTION_PAGE_COUNT);
            let pages_to_next_section = (MAX_SECTION_SIZE - (base.start_address().data() % MAX_SECTION_SIZE)) / PAGE_SIZE;
            let page_info_count = core::cmp::min(page_info_max_count, pages_to_next_section);

            let page_info_array_size_pages = (page_info_count * mem::size_of::<PageInfo>()).div_ceil(PAGE_SIZE);
            let page_info_array = unsafe {
                let base = allocator.allocate(FrameCount::new(page_info_array_size_pages)).expect("failed to allocate page info array");
                core::slice::from_raw_parts_mut(RmmA::phys_to_virt(base).data() as *mut PageInfo, page_info_count)
            };
            log::info!("page info at {page_info_array:p}");

            sections[i] = Section {
                base,
                frames: page_info_array,
            };
            i += 1;

            pages_left -= page_info_count;
            base = base.next_by(page_info_count);
        }
    }

    sections.sort_unstable_by_key(|s| s.base);

    // The bump allocator has been used during the section array and page info array allocation
    // phases, which means some of the PageInfos will be pointing to those arrays themselves.
    // Mark those pages as used!
    'sections: for section in &*sections {
        for (off, page_info) in section.frames.iter().enumerate() {
            let frame = section.base.next_by(off);
            if frame.start_address() >= allocator.abs_offset() {
                break 'sections;
            }
            log::info!("Marking {frame:?} as used");
            page_info.refcount.store(RC_USED_NOT_FREE, Ordering::Relaxed);
            page_info.next.store(0, Ordering::Relaxed);
        }
    }

    let mut first_pages: [Option<(Frame, &'static PageInfo)>; ORDER_COUNT as usize] = [None; ORDER_COUNT as usize];
    let mut last_pages = first_pages;

    log::info!("ABSOFF {:?}", Frame::containing(allocator.abs_offset()));

    let mut append_page = |page: Frame, info: &'static PageInfo, order| {
        let this_page = (page, info);

        if info.refcount.load(Ordering::Relaxed) & RC_USED_NOT_FREE == RC_USED_NOT_FREE {
            // Already marked as used by the section/page info arrays themselves.
            return;
        }

        let last_page = last_pages[order as usize].replace(this_page);

        if let Some((last_frame, last_page_info)) = last_page {
            last_page_info.as_free().unwrap().set_next(P2Frame::new(Some(page), order));
            info.as_free().unwrap().set_prev(P2Frame::new(Some(last_frame), order));
        } else {
            first_pages[order as usize] = Some(this_page);
        }
    };

    unsafe {
        ALLOCATOR_DATA = AllocatorData { sections };
    }

    for section in &*sections {
        let mut base = section.base;
        let mut frames = section.frames;

        for order in 0..=MAX_ORDER {
            let pages_for_current_order = 1 << order;

            if !frames.is_empty() && order != MAX_ORDER && !base.is_aligned_to_order(order + 1) {
                // The first section page is not aligned to the next order size.

                //log::info!("ORDER {order}: FIRST {base:?}");
                append_page(base, &frames[0], order);

                base = base.next_by(pages_for_current_order);
                frames = &frames[pages_for_current_order..];
            } else {
                //log::info!("ORDER {order}: FIRST SKIP");
            }

            if let Some(off2) = frames.len().checked_sub(2 * pages_for_current_order) && order != MAX_ORDER && !base.next_by(off2).is_aligned_to_order(order + 1) {
                // The last section page is not aligned to the next order size.

                let off = frames.len() - pages_for_current_order;

                //log::info!("ORDER {order}: LAST {base:?}");
                append_page(base.next_by(off), &frames[off], order);

                frames = &frames[..frames.len() - pages_for_current_order];
            } else {
                //log::info!("ORDER {order}: LAST SKIP");
            }

            if order == MAX_ORDER {
                assert_eq!(frames.len() % pages_for_current_order, 0);
                assert!(base.is_aligned_to_order(MAX_ORDER));

                for (off, info) in frames.iter().enumerate().step_by(pages_for_current_order) {
                    append_page(base.next_by(off), info, MAX_ORDER);
                }
            }
        }

        log::info!("SECTION from {:?}, {} pages", section.base, section.frames.len());
    }

    *FREELIST.lock() = first_pages.map(|pair| pair.map(|(frame, _)| frame));

    {
        let freelist = FREELIST.lock();

        for order in 0..=MAX_ORDER {
            let Some(first_frame) = freelist[order as usize] else {
                continue;
            };
            //log::info!("ORDER {order} FIRST {first_frame:?}");
            let mut frame = first_frame;

            while let Some(next) = get_page_info(frame).unwrap_or_else(|| panic!("no page info: {frame:?}")).as_free().expect("not free").next().frame() {
                //log::info!("ORDER {order} THEN {next:?}");
                frame = next;
            }
        }
    }

    let sections_page = Frame::containing(PhysicalAddress::new((unsafe { ALLOCATOR_DATA.sections }).as_ptr() as usize - crate::PHYS_OFFSET));
    let info = get_page_info(sections_page);
    log::info!("SECTIONS PAGE {sections_page:?} INFO {info:#0x?}");

    for section in unsafe { ALLOCATOR_DATA.sections } {
        let start = section.base;
        let page = Frame::containing(PhysicalAddress::new(section.frames.as_ptr() as usize - crate::PHYS_OFFSET));
        let info = get_page_info(page);
        log::info!("SECTIONS AT {start:?} PAGE {page:?} INFO {info:#0x?}");
    }
}

#[cold]
pub fn init_mm(allocator: BumpAllocator<RmmA>) {
    init_sections(allocator);

    unsafe {
        let the_frame = allocate_frame().expect("failed to allocate static zeroed frame");
        let the_info = get_page_info(the_frame).expect("static zeroed frame had no PageInfo");
        the_info
            .refcount
            .store(RefCount::One.to_raw(), Ordering::Relaxed);

        THE_ZEROED_FRAME.get().write(Some((the_frame, the_info)));
    }
}
#[derive(Debug)]
pub enum AddRefError {
    CowToShared,
    SharedToCow,
    RcOverflow,
}
impl PageInfo {
    pub fn new() -> Self {
        Self {
            refcount: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
        }
    }
    fn kind(&self) -> PageInfoKind<'_> {
        let next = self.next.load(Ordering::Relaxed);

        if next & RC_USED_NOT_FREE == RC_USED_NOT_FREE {
            PageInfoKind::Used(PageInfoUsed { refcount: &self.refcount, _misc: &self.next })
        } else {
            PageInfoKind::Free(PageInfoFree { prev: &self.refcount, next: &self.next, last_next: next })
        }
    }
    fn as_free(&self) -> Option<PageInfoFree<'_>> {
        match self.kind() {
            PageInfoKind::Free(f) => Some(f),
            PageInfoKind::Used(_) => None,
        }
    }
    pub fn add_ref(&self, kind: RefKind) -> Result<(), AddRefError> {
        match (self.refcount(), kind) {
            (RefCount::Zero, _) => self.refcount.store(RC_USED_NOT_FREE, Ordering::Relaxed),
            (RefCount::One, RefKind::Cow) => self.refcount.store(RC_USED_NOT_FREE | 1, Ordering::Relaxed),
            (RefCount::One, RefKind::Shared) => self.refcount.store(RC_USED_NOT_FREE | 1 | RC_SHARED_NOT_COW, Ordering::Relaxed),
            (RefCount::Cow(_), RefKind::Cow) | (RefCount::Shared(_), RefKind::Shared) => {
                let old = self.refcount.fetch_add(1, Ordering::Relaxed);

                if (old & RC_COUNT_MASK) >= RC_MAX {
                    self.refcount.fetch_sub(1, Ordering::Relaxed);
                    return Err(AddRefError::RcOverflow);
                }
            }
            (RefCount::Cow(_), RefKind::Shared) => return Err(AddRefError::CowToShared),
            (RefCount::Shared(_), RefKind::Cow) => return Err(AddRefError::SharedToCow),
        }
        Ok(())
    }
    #[must_use = "must deallocate if refcount reaches zero"]
    pub fn remove_ref(&self) -> RefCount {
        RefCount::from_raw(match self.refcount() {
            RefCount::Zero => panic!("refcount was already zero when calling remove_ref!"),
            RefCount::One => {
                // Used to be RC_USED_NOT_FREE | ?RC_SHARED_NOT_COW | 0, now becomes 0
                self.refcount.store(0, Ordering::Relaxed);

                0
            }
            RefCount::Cow(_) | RefCount::Shared(_) => {
                // Was RC_USED_NOT_FREE | ?RC_SHARED_NOW_COW | n, now becomes RC_USED_NOT_FREE |
                // ?RC_SHARED_NOW_COW | n - 1
                self.refcount.fetch_sub(1, Ordering::Relaxed) - 1
            },
        })
    }
    pub fn allows_writable(&self) -> bool {
        match self.refcount() {
            RefCount::Zero | RefCount::One => true,
            RefCount::Cow(_) => false,
            RefCount::Shared(_) => true,
        }
    }

    pub fn refcount(&self) -> RefCount {
        let refcount = self.refcount.load(Ordering::Relaxed);

        RefCount::from_raw(refcount)
    }
}
impl PageInfoFree<'_> {
    fn next(&self) -> P2Frame {
        P2Frame(self.next.load(Ordering::Relaxed))
    }
    fn set_next(&self, next: P2Frame) {
        self.next.store(next.0, Ordering::Relaxed)
    }
    fn prev(&self) -> P2Frame {
        P2Frame(self.prev.load(Ordering::Relaxed))
    }
    fn set_prev(&self, prev: P2Frame) {
        self.prev.store(prev.0, Ordering::Relaxed)
    }
    fn mark_used(&self) {
        self.next.store(0, Ordering::Relaxed);
        self.prev.store(0, Ordering::Relaxed);
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
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
    pub fn from_raw(raw: usize) -> Self {
        let refcount = raw & !RC_SHARED_NOT_COW;

        if let Some(nz_refcount) = NonZeroUsize::new(refcount) {
            if refcount == 1 {
                RefCount::One
            } else if raw & RC_SHARED_NOT_COW == RC_SHARED_NOT_COW {
                RefCount::Shared(nz_refcount)
            } else {
                RefCount::Cow(nz_refcount)
            }
        } else {
            RefCount::Zero
        }
    }
    pub fn to_raw(self) -> usize {
        match self {
            Self::Zero => 0,
            Self::One => 1,
            Self::Shared(inner) => inner.get() | RC_SHARED_NOT_COW,
            Self::Cow(inner) => inner.get(),
        }
    }
}
pub fn get_page_info(frame: Frame) -> Option<&'static PageInfo> {
    let sections = unsafe { ALLOCATOR_DATA.sections };

    let idx_res = sections.binary_search_by_key(&frame, |section| section.base);

    if idx_res == Err(0) {
        // The frame is before the first section
        return None;
    }

    // binary_search_by_key returns either Ok(where it was found) or Err(where it would have been
    // inserted). The base obviously cannot have been exactly matched from an entry at an
    // out-of-bounds index, so the only Err(i) where i - 1 is out of bounds, is for i=0. That
    // has already been checked.
    let section = &sections[idx_res.unwrap_or_else(|e| e - 1)];

    section.frames.get(frame.offset_from(section.base))

    /*
    sections
        .range(..=frame)
        .next_back()
        .filter(|(base, section)| frame <= base.next_by(section.frames.len()))
        .map(|(base, section)| PageInfoHandle { section, idx: frame.offset_from(*base) })
    */
}
pub struct Segv;

bitflags! {
    /// Arch-generic page fault flags, modeled after x86's error code.
    ///
    /// This may change when arch-specific features are utilized better.
    pub struct GenericPfFlags: u32 {
        const PRESENT = 1 << 0;
        const INVOLVED_WRITE = 1 << 1;
        const USER_NOT_SUPERVISOR = 1 << 2;
        const INSTR_NOT_DATA = 1 << 3;
        // "reserved bits" on x86
        const INVL = 1 << 31;
    }
}

pub trait ArchIntCtx {
    fn ip(&self) -> usize;
    fn recover_and_efault(&mut self);
}

pub fn page_fault_handler(
    stack: &mut impl ArchIntCtx,
    code: GenericPfFlags,
    faulting_address: VirtualAddress,
) -> Result<(), Segv> {
    let faulting_page = Page::containing_address(faulting_address);

    let usercopy_region = __usercopy_start()..__usercopy_end();

    // TODO: Most likely not necessary, but maybe also check that the faulting address is not too
    // close to USER_END.
    let address_is_user = faulting_address.kind() == TableKind::User;

    let invalid_page_tables = code.contains(GenericPfFlags::INVL);
    let caused_by_user = code.contains(GenericPfFlags::USER_NOT_SUPERVISOR);
    let caused_by_kernel = !caused_by_user;
    let caused_by_write = code.contains(GenericPfFlags::INVOLVED_WRITE);
    let caused_by_instr_fetch = code.contains(GenericPfFlags::INSTR_NOT_DATA);
    let is_usercopy = usercopy_region.contains(&stack.ip());

    let mode = match (caused_by_write, caused_by_instr_fetch) {
        (true, false) => AccessMode::Write,
        (false, false) => AccessMode::Read,
        (false, true) => AccessMode::InstrFetch,
        (true, true) => {
            unreachable!("page fault cannot be caused by both instruction fetch and write")
        }
    };

    if invalid_page_tables {
        // TODO: Better error code than Segv?
        return Err(Segv);
    }

    if address_is_user && (caused_by_user || is_usercopy) {
        match context::memory::try_correcting_page_tables(faulting_page, mode) {
            Ok(()) => return Ok(()),
            Err(PfError::Oom) => todo!("oom"),
            Err(PfError::Segv | PfError::RecursionLimitExceeded) => (),
            Err(PfError::NonfatalInternalError) => todo!(),
        }
    }

    if address_is_user && caused_by_kernel && mode != AccessMode::InstrFetch && is_usercopy {
        stack.recover_and_efault();
        return Ok(());
    }

    Err(Segv)
}
static THE_ZEROED_FRAME: SyncUnsafeCell<Option<(Frame, &'static PageInfo)>> =
    SyncUnsafeCell::new(None);

pub fn the_zeroed_frame() -> (Frame, &'static PageInfo) {
    unsafe {
        THE_ZEROED_FRAME
            .get()
            .read()
            .expect("zeroed frame must be initialized")
    }
}

pub fn init_frame(init_rc: RefCount) -> Result<Frame, PfError> {
    let new_frame = crate::memory::allocate_frame().ok_or(PfError::Oom)?;
    let page_info = get_page_info(new_frame).unwrap_or_else(|| panic!("all allocated frames need an associated page info, {:?} didn't", new_frame));
    assert_eq!(page_info.refcount(), RefCount::Zero);
    page_info
        .refcount
        .store(init_rc.to_raw(), Ordering::Relaxed);

    Ok(new_frame)
}
#[derive(Debug)]
pub struct TheFrameAllocator;

impl FrameAllocator for TheFrameAllocator {
    unsafe fn allocate(&mut self, count: FrameCount) -> Option<PhysicalAddress> {
        allocate_frames(count.data()).map(|f| f.start_address())
    }
    unsafe fn free(&mut self, address: PhysicalAddress, count: FrameCount) {
        deallocate_frames(Frame::containing_address(address), count.data())
    }
    unsafe fn usage(&self) -> rmm::FrameUsage {
        todo!()
    }
}
impl FreeList {
    pub fn new() -> Self {
        Self {
            for_orders: [None; ORDER_COUNT as usize],
        }
    }
}
