//! # Memory management
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/allocating-frames.html)

mod kernel_mapper;

use core::{
    cell::SyncUnsafeCell,
    mem,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};

pub use kernel_mapper::KernelMapper;
use spin::Mutex;

pub use crate::paging::{PhysicalAddress, RmmA, RmmArch, PAGE_MASK, PAGE_SIZE};
use crate::{
    context::{
        self,
        memory::{AccessMode, PfError},
    },
    kernel_executable_offsets::{__usercopy_end, __usercopy_start},
    paging::{entry::EntryFlags, Page, PageFlags},
    syscall::error::{Error, ENOMEM},
};
use rmm::{BumpAllocator, FrameAllocator, FrameCount, FrameUsage, TableKind, VirtualAddress};

/// Available physical memory areas
pub(crate) static AREAS: SyncUnsafeCell<[rmm::MemoryArea; 512]> = SyncUnsafeCell::new(
    [rmm::MemoryArea {
        base: PhysicalAddress::new(0),
        size: 0,
    }; 512],
);
pub(crate) static AREA_COUNT: SyncUnsafeCell<u16> = SyncUnsafeCell::new(0);

// TODO: Share code
pub(crate) fn areas() -> &'static [rmm::MemoryArea] {
    // SAFETY: Both AREAS and AREA_COUNT are initialized once and then never changed.
    //
    // TODO: Memory hotplug?
    unsafe { &(&*AREAS.get())[..AREA_COUNT.get().read().into()] }
}

/// Get the number of frames available
pub fn free_frames() -> usize {
    total_frames() - used_frames()
}

/// Get the number of frames used
pub fn used_frames() -> usize {
    // TODO: Include bump allocator static pages?
    FREELIST.lock().used_frames
}
pub fn total_frames() -> usize {
    // TODO: Include bump allocator static pages?
    sections().iter().map(|section| section.frames.len()).sum()
}

/// Allocate a range of frames
pub fn allocate_p2frame(order: u32) -> Option<Frame> {
    allocate_p2frame_complex(order, (), None, order).map(|(f, _)| f)
}
pub fn allocate_frame() -> Option<Frame> {
    allocate_p2frame(0)
}
// TODO: Flags, strategy
pub fn allocate_p2frame_complex(
    _req_order: u32,
    _flags: (),
    _strategy: Option<()>,
    min_order: u32,
) -> Option<(Frame, usize)> {
    let mut freelist = FREELIST.lock();

    let Some((frame_order, frame)) = freelist
        .for_orders
        .iter()
        .enumerate()
        .skip(min_order as usize)
        .find_map(|(i, f)| f.map(|f| (i as u32, f)))
    else {
        return None;
    };

    let info = get_page_info(frame)
        .unwrap_or_else(|| panic!("no page info for allocated frame {frame:?}"))
        .as_free()
        .expect("freelist frames must not be marked used!");
    let next_free = info.next();
    //log::info!("FREE {frame:?} ORDER {frame_order} NEXT_FREE {next_free:?}");

    debug_assert_eq!(
        next_free.order(),
        frame_order,
        "{frame:?}->next {next_free:?}.order != {frame_order}"
    );
    if let Some(next) = next_free.frame() {
        let f = get_free_alloc_page_info(next);
        debug_assert_eq!(f.prev().frame(), Some(frame));
        debug_assert_ne!(next, frame);
        debug_assert!(
            next.is_aligned_to_order(frame_order),
            "NEXT {next:?} UNALIGNED"
        );
        f.set_prev(P2Frame::new(None, frame_order));
    }

    debug_assert!(frame.is_aligned_to_order(frame_order));
    debug_assert_eq!(next_free.order(), frame_order);
    freelist.for_orders[frame_order as usize] = next_free.frame();

    // TODO: Is this LIFO cache optimal?
    //log::info!("MIN{min_order}FRAMEORD{frame_order}");
    for order in (min_order..frame_order).rev() {
        //log::info!("SPLIT ORDER {order}");
        let order_page_count = 1 << order;

        let hi = frame.next_by(order_page_count);
        //log::info!("SPLIT INTO {frame:?}:{hi:?} ORDER {order}");

        debug_assert_eq!(freelist.for_orders[order as usize], None);

        let hi_info = get_page_info(hi)
            .expect("sub-p2frame of split p2flame lacked PageInfo")
            .make_free(order);
        debug_assert!(!hi.is_aligned_to_order(frame_order));
        debug_assert!(hi.is_aligned_to_order(order));
        hi_info.set_next(P2Frame::new(None, order));
        hi_info.set_prev(P2Frame::new(None, order));
        freelist.for_orders[order as usize] = Some(hi);
    }

    freelist.used_frames += 1 << min_order;

    info.mark_used();
    drop(freelist);

    unsafe {
        (RmmA::phys_to_virt(frame.base()).data() as *mut u8).write_bytes(0, PAGE_SIZE << min_order);
    }

    debug_assert!(frame.base().data() >= unsafe { ALLOCATOR_DATA.abs_off });

    Some((frame, PAGE_SIZE << min_order))
}

pub unsafe fn deallocate_p2frame(orig_frame: Frame, order: u32) {
    let mut freelist = FREELIST.lock();
    let mut largest_order = order;

    let mut current = orig_frame;

    for merge_order in order..MAX_ORDER {
        // Because there's a PageInfo, this frame must be allocator-owned. We need to be very
        // careful with who owns this page, as the refcount can be anything from 0 (undefined) to
        // 2^addrwidth - 1. However, allocation and deallocation must be synchronized (the "next"
        // word of the PageInfo).

        let sibling = Frame::containing(PhysicalAddress::new(
            current.base().data() ^ (PAGE_SIZE << merge_order),
        ));

        let Some(_cur_info) = get_page_info(current) else {
            unreachable!("attempting to free non-allocator-owned page");
        };

        let Some(sib_info) = get_page_info(sibling) else {
            // The frame that was deallocated, was at the unaligned start or end of its section
            // (i.e. there aren't 1 << merge_order additional pages).
            break;
        };

        let PageInfoKind::Free(sib_info) = sib_info.kind() else {
            // The frame is currently in use (refcounted). It cannot be merged!
            break;
        };

        // If the sibling p2frame has lower order than merge_order, it cannot be merged into
        // current.
        if sib_info.next().order() < merge_order {
            break;
        }
        debug_assert!(
            !(sib_info.next().order() > merge_order),
            "sibling page has unaligned order or contains current page"
        );
        //log::info!("MERGED {lo:?} WITH {hi:?} ORDER {order}");

        if let Some(sib_prev) = sib_info.prev().frame() {
            get_free_alloc_page_info(sib_prev).set_next(sib_info.next());
        } else {
            debug_assert_eq!(freelist.for_orders[merge_order as usize], Some(sibling));
            debug_assert!(sib_info
                .next()
                .frame()
                .map_or(true, |f| f.is_aligned_to_order(merge_order)));
            debug_assert_eq!(sib_info.next().order(), merge_order);
            freelist.for_orders[merge_order as usize] = sib_info.next().frame();
        }
        if let Some(sib_next) = sib_info.next().frame() {
            get_free_alloc_page_info(sib_next).set_prev(sib_info.prev());
        }

        current = Frame::containing(PhysicalAddress::new(
            current.base().data() & !(PAGE_SIZE << merge_order),
        ));

        largest_order = merge_order + 1;
    }
    get_page_info(current)
        .expect("freeing frame without PageInfo")
        .make_free(largest_order);

    let new_head = current;
    debug_assert!(new_head.is_aligned_to_order(largest_order));

    if let Some(old_head) = freelist.for_orders[largest_order as usize].replace(new_head) {
        //log::info!("HEAD {:p} FREED {:p} BARRIER {:p}", get_page_info(old_head).unwrap(), get_page_info(frame).unwrap(), unsafe { ALLOCATOR_DATA.abs_off as *const u8 });
        let old_head_info = get_free_alloc_page_info(old_head);
        let new_head_info = get_free_alloc_page_info(new_head);

        new_head_info.set_next(P2Frame::new(Some(old_head), largest_order));
        new_head_info.set_prev(P2Frame::new(None, largest_order));
        old_head_info.set_prev(P2Frame::new(Some(new_head), largest_order));
    }

    //log::info!("FREED {frame:?}+2^{order}");
    freelist.used_frames -= 1 << order;
}

pub unsafe fn deallocate_frame(frame: Frame) {
    deallocate_p2frame(frame, 0)
}

// Helper function for quickly mapping device memory
pub unsafe fn map_device_memory(addr: PhysicalAddress, len: usize) -> VirtualAddress {
    let mut mapper_lock = KernelMapper::lock();
    let mapper = mapper_lock
        .get_mut()
        .expect("KernelMapper mapper locked re-entrant in map_device_memory");
    let base = PhysicalAddress::new(crate::paging::round_down_pages(addr.data()));
    let aligned_len = crate::paging::round_up_pages(len + (addr.data() - base.data()));
    for page_idx in 0..aligned_len / crate::memory::PAGE_SIZE {
        let (_, flush) = mapper
            .map_linearly(
                base.add(page_idx * crate::memory::PAGE_SIZE),
                PageFlags::new()
                    .write(true)
                    .custom_flag(EntryFlags::NO_CACHE.bits(), true),
            )
            .expect("failed to linearly map SDT");
        flush.flush();
    }
    RmmA::phys_to_virt(addr)
}

const ORDER_COUNT: u32 = 11;
const MAX_ORDER: u32 = ORDER_COUNT - 1;

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
        Self(frame.map_or(0, |f| f.physaddr.get()) | (order as usize))
    }
    fn get(self) -> (Option<Frame>, u32) {
        let page_off_mask = PAGE_SIZE - 1;
        (
            NonZeroUsize::new(self.0 & !page_off_mask & !RC_USED_NOT_FREE)
                .map(|physaddr| Frame { physaddr }),
            (self.0 & page_off_mask) as u32,
        )
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
        write!(f, "[frame at {:p}]", self.base().data() as *const u8)
    }
}

impl Frame {
    /// Create a frame containing `address`
    pub fn containing(address: PhysicalAddress) -> Frame {
        Frame {
            physaddr: NonZeroUsize::new(address.data() & !PAGE_MASK)
                .expect("frame 0x0 is reserved"),
        }
    }

    /// Get the address of this frame
    pub fn base(self) -> PhysicalAddress {
        PhysicalAddress::new(self.physaddr.get())
    }

    //TODO: Set private
    pub fn range_inclusive(start: Frame, end: Frame) -> impl Iterator<Item = Frame> {
        (start.physaddr.get()..=end.physaddr.get())
            .step_by(PAGE_SIZE)
            .map(|number| Frame {
                physaddr: NonZeroUsize::new(number).unwrap(),
            })
    }
    #[track_caller]
    pub fn next_by(self, n: usize) -> Self {
        Self {
            physaddr: self
                .physaddr
                .get()
                .checked_add(n * PAGE_SIZE)
                .and_then(NonZeroUsize::new)
                .expect("overflow or null in Frame::next_by"),
        }
    }
    pub fn offset_from(self, from: Self) -> usize {
        self.physaddr
            .get()
            .checked_sub(from.physaddr.get())
            .expect("overflow in Frame::offset_from")
            / PAGE_SIZE
    }
    pub fn is_aligned_to_order(self, order: u32) -> bool {
        self.base().data() % (PAGE_SIZE << order) == 0
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
    pub unsafe fn new_unchecked(inner: Frame) -> Self {
        Self { inner }
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
            == None
        {
            unsafe {
                deallocate_frame(self.inner);
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
    _refcount: &'info AtomicUsize,
    _misc: &'info AtomicUsize,
}
struct PageInfoFree<'info> {
    prev: &'info AtomicUsize,
    next: &'info AtomicUsize,
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

static mut ALLOCATOR_DATA: AllocatorData = AllocatorData {
    sections: &[],
    abs_off: 0,
};

struct AllocatorData {
    // TODO: Memory hotplugging?
    sections: &'static [Section],
    abs_off: usize,
}
#[derive(Debug)]
struct FreeList {
    for_orders: [Option<Frame>; ORDER_COUNT as usize],
    used_frames: usize,
}
static FREELIST: Mutex<FreeList> = Mutex::new(FreeList {
    for_orders: [None; ORDER_COUNT as usize],
    used_frames: 0,
});

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

    let free_areas_iter = || {
        free_areas.iter().copied().enumerate().map(|(i, area)| {
            if i == 0 {
                rmm::MemoryArea {
                    base: area.base.add(offset_into_first_free_area),
                    size: area.size - offset_into_first_free_area,
                }
            } else {
                area
            }
        })
    };

    let sections: &'static mut [Section] = {
        let max_section_count: usize = free_areas_iter()
            .map(|area| {
                let aligned_end = area
                    .base
                    .add(area.size)
                    .data()
                    .next_multiple_of(MAX_SECTION_SIZE);
                let aligned_start = area.base.data() / MAX_SECTION_SIZE * MAX_SECTION_SIZE;

                (aligned_end - aligned_start) / MAX_SECTION_SIZE
            })
            .sum();
        let section_array_page_count =
            (max_section_count * mem::size_of::<Section>()).div_ceil(PAGE_SIZE);

        unsafe {
            let base = allocator
                .allocate(FrameCount::new(section_array_page_count))
                .expect("failed to allocate sections array");
            core::slice::from_raw_parts_mut(
                RmmA::phys_to_virt(base).data() as *mut Section,
                max_section_count,
            )
        }
    };

    let mut iter = free_areas_iter().peekable();

    let mut i = 0;

    while let Some(mut memory_map_area) = iter.next() {
        // TODO: NonZeroUsize

        // TODO: x86_32 fails without this check
        if memory_map_area.size == 0 {
            continue;
        }

        assert_ne!(
            memory_map_area.size, 0,
            "RMM should enforce areas are not zeroed"
        );

        // TODO: Should RMM do this?

        while let Some(next_area) = iter.peek()
            && next_area.base == memory_map_area.base.add(memory_map_area.size)
        {
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
        let mut base = Frame::containing(memory_map_area.base);

        while pages_left > 0 {
            let page_info_max_count = core::cmp::min(pages_left, MAX_SECTION_PAGE_COUNT);
            let pages_to_next_section =
                (MAX_SECTION_SIZE - (base.base().data() % MAX_SECTION_SIZE)) / PAGE_SIZE;
            let page_info_count = core::cmp::min(page_info_max_count, pages_to_next_section);

            let page_info_array_size_pages =
                (page_info_count * mem::size_of::<PageInfo>()).div_ceil(PAGE_SIZE);
            let page_info_array = unsafe {
                let base = allocator
                    .allocate(FrameCount::new(page_info_array_size_pages))
                    .expect("failed to allocate page info array");
                core::slice::from_raw_parts_mut(
                    RmmA::phys_to_virt(base).data() as *mut PageInfo,
                    page_info_count,
                )
            };
            for p in &*page_info_array {
                assert_eq!(p.next.load(Ordering::Relaxed), 0);
                assert_eq!(p.refcount.load(Ordering::Relaxed), 0);
            }

            sections[i] = Section {
                base,
                frames: page_info_array,
            };
            i += 1;

            pages_left -= page_info_count;
            base = base.next_by(page_info_count);
        }
    }
    let sections = &mut sections[..i];

    sections.sort_unstable_by_key(|s| s.base);

    // The bump allocator has been used during the section array and page info array allocation
    // phases, which means some of the PageInfos will be pointing to those arrays themselves.
    // Mark those pages as used!
    'sections: for section in &*sections {
        for (off, page_info) in section.frames.iter().enumerate() {
            let frame = section.base.next_by(off);
            if frame.base() >= allocator.abs_offset() {
                break 'sections;
            }
            //log::info!("MARKING {frame:?} AS USED");
            page_info
                .refcount
                .store(RC_USED_NOT_FREE, Ordering::Relaxed);
            page_info.next.store(0, Ordering::Relaxed);
        }
    }

    let mut first_pages: [Option<(Frame, &'static PageInfo)>; ORDER_COUNT as usize] =
        [None; ORDER_COUNT as usize];
    let mut last_pages = first_pages;

    let mut append_page = |page: Frame, info: &'static PageInfo, order| {
        let this_page = (page, info);

        if page.base() < allocator.abs_offset() {
            return;
        }
        debug_assert!(info.as_free().is_some());
        debug_assert!(this_page.0.is_aligned_to_order(order));
        debug_assert_eq!(info.next.load(Ordering::Relaxed), order as usize);
        debug_assert_eq!(info.refcount.load(Ordering::Relaxed), 0);

        let last_page = last_pages[order as usize].replace(this_page);

        if let Some((last_frame, last_page_info)) = last_page {
            let last_info = last_page_info.as_free().unwrap();

            debug_assert_eq!(last_info.next().order(), order);
            debug_assert_eq!(last_info.next().frame(), None);

            last_info.set_next(P2Frame::new(Some(page), order));
            info.as_free()
                .unwrap()
                .set_prev(P2Frame::new(Some(last_frame), order));
        } else {
            first_pages[order as usize] = Some(this_page);
            info.as_free().unwrap().set_prev(P2Frame::new(None, order));
            info.as_free().unwrap().set_next(P2Frame::new(None, order));
        }
    };
    unsafe {
        ALLOCATOR_DATA = AllocatorData {
            sections,
            abs_off: allocator.abs_offset().data(),
        };
    }

    for section in &*sections {
        let mut base = section.base;
        let mut frames = section.frames;

        for order in 0..=MAX_ORDER {
            let pages_for_current_order = 1 << order;

            debug_assert_eq!(frames.len() % pages_for_current_order, 0);
            debug_assert!(base.is_aligned_to_order(order));

            if !frames.is_empty() && order != MAX_ORDER && !base.is_aligned_to_order(order + 1) {
                frames[0].next.store(order as usize, Ordering::Relaxed);
                // The first section page is not aligned to the next order size.

                //log::info!("ORDER {order}: FIRST {base:?}");
                append_page(base, &frames[0], order);

                base = base.next_by(pages_for_current_order);
                frames = &frames[pages_for_current_order..];
            } else {
                //log::info!("ORDER {order}: FIRST SKIP");
            }

            if !frames.is_empty()
                && order != MAX_ORDER
                && !base.next_by(frames.len()).is_aligned_to_order(order + 1)
            {
                // The last section page is not aligned to the next order size.

                let off = frames.len() - pages_for_current_order;
                let final_page = base.next_by(off);

                frames[off].next.store(order as usize, Ordering::Relaxed);

                //log::info!("ORDER {order}: LAST {final_page:?}");
                append_page(final_page, &frames[off], order);

                frames = &frames[..off];
            } else {
                //log::info!("ORDER {order}: LAST SKIP");
            }

            if frames.is_empty() {
                break;
            }

            if order == MAX_ORDER {
                debug_assert_eq!(frames.len() % pages_for_current_order, 0);
                debug_assert!(base.is_aligned_to_order(MAX_ORDER));

                for (off, info) in frames.iter().enumerate().step_by(pages_for_current_order) {
                    info.next.store(MAX_ORDER as usize, Ordering::Relaxed);
                    append_page(base.next_by(off), info, MAX_ORDER);
                }
            }
        }

        //log::info!("SECTION from {:?}, {} pages, array at {:p}", section.base, section.frames.len(), section.frames);
    }
    for (order, tuple_opt) in last_pages.iter().enumerate() {
        let Some((frame, info)) = tuple_opt else {
            continue;
        };
        debug_assert!(frame.is_aligned_to_order(order as u32));
        let free = info.as_free().unwrap();
        debug_assert_eq!(free.prev().order(), order as u32);
        free.set_next(P2Frame::new(None, order as u32));
    }

    FREELIST.lock().for_orders = first_pages.map(|pair| pair.map(|(frame, _)| frame));

    //debug_freelist();
    log::info!("Initial freelist consistent");
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
#[derive(Debug, PartialEq)]
pub enum AddRefError {
    CowToShared,
    SharedToCow,
    RcOverflow,
}
impl PageInfo {
    fn kind(&self) -> PageInfoKind<'_> {
        let prev = self.refcount.load(Ordering::Relaxed);

        if prev & RC_USED_NOT_FREE == RC_USED_NOT_FREE {
            PageInfoKind::Used(PageInfoUsed {
                _refcount: &self.refcount,
                _misc: &self.next,
            })
        } else {
            PageInfoKind::Free(PageInfoFree {
                prev: &self.refcount,
                next: &self.next,
            })
        }
    }
    fn as_free(&self) -> Option<PageInfoFree<'_>> {
        match self.kind() {
            PageInfoKind::Free(f) => Some(f),
            PageInfoKind::Used(_) => None,
        }
    }
    pub fn add_ref(&self, kind: RefKind) -> Result<(), AddRefError> {
        match (self.refcount().expect("cannot add_ref to free frame"), kind) {
            (RefCount::One, RefKind::Cow) => {
                self.refcount.store(RC_USED_NOT_FREE | 1, Ordering::Relaxed)
            }
            (RefCount::One, RefKind::Shared) => self
                .refcount
                .store(RC_USED_NOT_FREE | 1 | RC_SHARED_NOT_COW, Ordering::Relaxed),
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
    #[must_use = "must deallocate if refcount reaches None"]
    pub fn remove_ref(&self) -> Option<RefCount> {
        match self.refcount() {
            None => panic!("refcount was already zero when calling remove_ref!"),
            Some(RefCount::One) => {
                // Used to be RC_USED_NOT_FREE | ?RC_SHARED_NOT_COW | 0, now becomes 0
                //self.refcount.store(0, Ordering::Relaxed);

                None
            }
            Some(RefCount::Cow(_) | RefCount::Shared(_)) => RefCount::from_raw({
                // Used to be RC_USED_NOT_FREE | ?RC_SHARED_NOW_COW | n, now becomes
                // RC_USED_NOT_FREE | ?RC_SHARED_NOW_COW | n - 1
                (self.refcount.fetch_sub(1, Ordering::Relaxed) - 1) | RC_USED_NOT_FREE
            }),
        }
    }
    #[track_caller]
    pub fn allows_writable(&self) -> bool {
        match self
            .refcount()
            .expect("using allows_writable on free page!")
        {
            RefCount::One => true,
            RefCount::Cow(_) => false,
            RefCount::Shared(_) => true,
        }
    }

    pub fn refcount(&self) -> Option<RefCount> {
        let refcount = self.refcount.load(Ordering::Relaxed);

        RefCount::from_raw(refcount)
    }
    fn make_free(&self, order: u32) -> PageInfoFree<'_> {
        // Order needs to be known so we don't for example merge A: [A] A A A B: [B] U U U into a
        // 2^3 page (if U indicates "used").
        self.refcount.store(order as usize, Ordering::Relaxed);
        self.next.store(order as usize, Ordering::Relaxed);

        PageInfoFree {
            next: &self.next,
            prev: &self.refcount,
        }
    }
}
impl PageInfoFree<'_> {
    fn next(&self) -> P2Frame {
        P2Frame(self.next.load(Ordering::Relaxed))
    }
    #[track_caller]
    fn set_next(&self, next: P2Frame) {
        debug_assert!(next
            .frame()
            .map_or(true, |f| f.is_aligned_to_order(next.order())));
        self.next.store(next.0, Ordering::Relaxed)
    }
    fn prev(&self) -> P2Frame {
        P2Frame(self.prev.load(Ordering::Relaxed))
    }
    fn set_prev(&self, prev: P2Frame) {
        debug_assert!(prev
            .frame()
            .map_or(true, |f| f.is_aligned_to_order(prev.order())));
        self.prev.store(prev.0, Ordering::Relaxed)
    }
    fn mark_used(&self) {
        // Order is irrelevant if marked "used"
        self.prev.store(RC_USED_NOT_FREE, Ordering::Relaxed);
        self.next.store(0, Ordering::Relaxed);
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
    One,
    Shared(NonZeroUsize),
    Cow(NonZeroUsize),
}
impl RefCount {
    pub fn from_raw(raw: usize) -> Option<Self> {
        if raw & RC_USED_NOT_FREE != RC_USED_NOT_FREE {
            return None;
        }
        let refcount_minus_one = raw & !(RC_SHARED_NOT_COW | RC_USED_NOT_FREE);
        let nz_refcount = NonZeroUsize::new(refcount_minus_one + 1).unwrap();

        Some(if nz_refcount.get() == 1 {
            RefCount::One
        } else if raw & RC_SHARED_NOT_COW == RC_SHARED_NOT_COW {
            RefCount::Shared(nz_refcount)
        } else {
            RefCount::Cow(nz_refcount)
        })
    }
    pub fn to_raw(self) -> usize {
        match self {
            Self::One => 0 | RC_USED_NOT_FREE,
            Self::Shared(inner) => (inner.get() - 1) | RC_SHARED_NOT_COW | RC_USED_NOT_FREE,
            Self::Cow(inner) => (inner.get() - 1) | RC_USED_NOT_FREE,
        }
    }
}
#[inline]
fn sections() -> &'static [Section] {
    unsafe { ALLOCATOR_DATA.sections }
}
pub fn get_page_info(frame: Frame) -> Option<&'static PageInfo> {
    let sections = sections();

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

#[track_caller]
fn get_free_alloc_page_info(frame: Frame) -> PageInfoFree<'static> {
    let i = get_page_info(frame).unwrap_or_else(|| {
        panic!("allocator-owned frames need a PageInfo, but none for {frame:?}")
    });
    i.as_free().unwrap() //.unwrap_or_else(|| panic!("expected frame to be free, but {frame:?} wasn't, in {i:?}"))
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
    let new_frame = allocate_frame().ok_or(PfError::Oom)?;
    let page_info = get_page_info(new_frame).unwrap_or_else(|| {
        panic!(
            "all allocated frames need an associated page info, {:?} didn't",
            new_frame
        )
    });
    debug_assert_eq!(page_info.refcount(), Some(RefCount::One));
    page_info
        .refcount
        .store(init_rc.to_raw(), Ordering::Relaxed);

    Ok(new_frame)
}
#[derive(Debug)]
pub struct TheFrameAllocator;

impl FrameAllocator for TheFrameAllocator {
    unsafe fn allocate(&mut self, count: FrameCount) -> Option<PhysicalAddress> {
        let order = count.data().next_power_of_two().trailing_zeros();
        allocate_p2frame(order).map(|f| f.base())
    }
    unsafe fn free(&mut self, address: PhysicalAddress, count: FrameCount) {
        let order = count.data().next_power_of_two().trailing_zeros();
        deallocate_p2frame(Frame::containing(address), order)
    }
    unsafe fn usage(&self) -> FrameUsage {
        FrameUsage::new(
            FrameCount::new(used_frames()),
            FrameCount::new(total_frames()),
        )
    }
}
