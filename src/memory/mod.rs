//! # Memory management
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/allocating-frames.html)

use core::{
    cell::SyncUnsafeCell,
    mem,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};

pub use crate::paging::{PhysicalAddress, RmmA, RmmArch, PAGE_SIZE};
use crate::paging::Page;
use crate::context::{self, memory::{AccessMode, PfError}};
use crate::kernel_executable_offsets::{__usercopy_start, __usercopy_end};
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
    todo!()
}

const ORDER_COUNT: u32 = 11;

pub struct FreeList {
    for_orders: [Option<Frame>; ORDER_COUNT as usize],
}

/// Deallocate a range of frames frame
pub unsafe fn deallocate_frames(frame: Frame, count: usize) {
    todo!()
}
pub unsafe fn deallocate_frame(frame: Frame) {
    deallocate_frames(frame, 1)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Frame {
    // On x86/x86_64, all memory below 1 MiB is reserved, and although some frames in that range
    // may end up in the paging code, it's very unlikely that frame 0x0 would.
    number: NonZeroUsize,
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
    pub fn start_address(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.number.get() * PAGE_SIZE)
    }

    /// Create a frame containing `address`
    pub fn containing_address(address: PhysicalAddress) -> Frame {
        Frame {
            number: NonZeroUsize::new(address.data() / PAGE_SIZE).expect("frame 0x0 is reserved"),
        }
    }

    //TODO: Set private
    pub fn range_inclusive(start: Frame, end: Frame) -> impl Iterator<Item = Frame> {
        (start.number.get()..=end.number.get()).map(|number| Frame { number: NonZeroUsize::new(number).unwrap() })
    }
    pub fn next_by(self, n: usize) -> Self {
        Self {
            number: self
                .number
                .get()
                .checked_add(n)
                .and_then(NonZeroUsize::new)
                .expect("overflow in Frame::next_by"),
        }
    }
    pub fn offset_from(self, from: Self) -> usize {
        self.number
            .get()
            .checked_sub(from.number.get())
            .expect("overflow in Frame::offset_from")
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

    // TODO: Needs to be atomic, or we can introduce some form of lock.
    //
    // TODO: Add one flag indicating whether the page contents is zeroed? Or should this primarily
    // be managed by the memory allocator first?
    pub flags: FrameFlags,
}
const RC_SHARED_NOT_COW: usize = 1 << (usize::BITS - 1);

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
    let sections: &'static mut [Section] = {
        let max_section_count: usize = allocator.areas().iter().map(|area| {
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

    let mut iter = allocator.areas().iter().copied().peekable();

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
                core::slice::from_raw_parts_mut(base.data() as *mut PageInfo, page_info_count)
            };

            sections[i] = Section {
                base,
                frames: page_info_array,
            };
            i += 1;

            pages_left -= page_info_count;
            base = base.next_by(page_info_count);
        }
    }

    for section in &*sections {
        //log::info!("SECTION from {:?}, {} pages", section.base, section.frames.len());
    }

    sections.sort_unstable_by_key(|s| s.base);

    unsafe {
        ALLOCATOR_DATA = AllocatorData { sections };
    }
    loop {}
}

#[cold]
pub fn init_mm(allocator: BumpAllocator<RmmA>) {
    init_sections(allocator);

    unsafe {
        let the_frame = allocate_frames(1).expect("failed to allocate static zeroed frame");
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
}
impl PageInfo {
    pub fn add_ref(&self, kind: RefKind) -> Result<(), AddRefError> {
        match (self.refcount(), kind) {
            (RefCount::Zero, _) => self.refcount.store(1, Ordering::Relaxed),
            (RefCount::One, RefKind::Cow) => self.refcount.store(2, Ordering::Relaxed),
            (RefCount::One, RefKind::Shared) => self
                .refcount
                .store(2 | RC_SHARED_NOT_COW, Ordering::Relaxed),
            (RefCount::Cow(_), RefKind::Cow) | (RefCount::Shared(_), RefKind::Shared) => {
                self.refcount.fetch_add(1, Ordering::Relaxed);
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
                self.refcount.store(0, Ordering::Relaxed);

                0
            }
            RefCount::Cow(_) | RefCount::Shared(_) => {
                self.refcount.fetch_sub(1, Ordering::Relaxed) - 1
            }
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
