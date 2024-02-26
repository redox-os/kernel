//! # Memory management
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/allocating-frames.html)

use core::{
    cell::SyncUnsafeCell,
    mem,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};

pub use crate::paging::{PhysicalAddress, RmmA, RmmArch, PAGE_SIZE};
use crate::{
    arch::rmm::LockedAllocator,
    context::{
        self,
        memory::{AccessMode, PfError},
    },
    kernel_executable_offsets::{__usercopy_end, __usercopy_start},
    paging::Page,
    rmm::areas,
};

use crate::syscall::error::{Error, ENOMEM};
use alloc::vec::Vec;
use rmm::{FrameAllocator, FrameCount, TableKind, VirtualAddress};
use spin::RwLock;

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
    unsafe { LockedAllocator.usage().free().data() }
}

/// Get the number of frames used
pub fn used_frames() -> usize {
    unsafe { LockedAllocator.usage().used().data() }
}

/// Allocate a range of frames
pub fn allocate_frames(count: usize) -> Option<Frame> {
    unsafe {
        LockedAllocator
            .allocate(FrameCount::new(count))
            .map(|phys| Frame::containing_address(PhysicalAddress::new(phys.data())))
    }
}
// TODO: allocate_frames_complex

/// Deallocate a range of frames frame
// TODO: Make unsafe
pub fn deallocate_frames(frame: Frame, count: usize) {
    unsafe {
        LockedAllocator.free(
            rmm::PhysicalAddress::new(frame.start_address().data()),
            FrameCount::new(count),
        );
    }
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
    pub fn range_inclusive(start: Frame, end: Frame) -> FrameIter {
        FrameIter { start, end }
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
            crate::memory::deallocate_frames(self.inner, 1);
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

// TODO: Very read-heavy RwLock? ArcSwap? Store the struct in percpu, and in the *very* unlikely
// event of hotplugging, do IPIs to force all CPUs to update the sections.
//
// XXX: Is it possible to safely initialize an empty boxed slice from a const context?
//pub static SECTIONS: RwLock<Box<[&'static Section]>> = RwLock::new(Box::new([]));
pub static SECTIONS: RwLock<Vec<Section>> = RwLock::new(Vec::new());

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
fn init_sections() {
    let mut guard = SECTIONS.write();
    let mut sections = Vec::new();

    let mut iter = areas().iter().copied().peekable();

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
            let section_page_count = core::cmp::min(pages_left, MAX_SECTION_PAGE_COUNT);

            // Avoid Vec here as we are currently initializing data structures
            // required by the global allocator.

            let Ok(layout) = core::alloc::Layout::array::<PageInfo>(section_page_count) else {
                panic!("failed to allocate static frame sections: length overflow");
            };
            assert!(layout.align() <= PAGE_SIZE);

            // We use the fact that allocate_frames returns zeroed frames. We
            // want every element to be the default initialized value, which
            // consists entirely of zero bytes.
            let phys = allocate_frames(layout.size().div_ceil(PAGE_SIZE))
                .expect("failed to allocate static frame sections");

            let mut frames = unsafe {
                let virt = RmmA::phys_to_virt(phys.start_address()).data();

                core::slice::from_raw_parts_mut(virt as *mut PageInfo, section_page_count)
            };

            sections.push(Section { base, frames });

            pages_left -= section_page_count;
            base = base.next_by(section_page_count);
        }
    }

    /*
    for section in &sections {
        log::info!("SECTION from {:?}, {} pages", section.base, section.frames.len());
    }
    */

    sections.sort_unstable_by_key(|s| s.base);
    sections.shrink_to_fit();

    *guard = sections;
}

#[cold]
pub fn init_mm() {
    init_sections();

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
    let sections = SECTIONS.read();

    let idx_res = sections.binary_search_by_key(&frame, |section| section.base);

    if idx_res == Err(0) || idx_res == Err(sections.len()) {
        return None;
    }

    // binary_search_by_key returns either Ok(where it was found) or Err(where it would have been
    // inserted). The base obviously cannot have been exactly matched from an entry at an
    // out-of-bounds index, so the only Err(i) where i is out of bounds, is for i=0 and i=len. That
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
    let new_frame = crate::memory::allocate_frames(1).ok_or(PfError::Oom)?;
    let page_info = get_page_info(new_frame).unwrap_or_else(|| {
        panic!(
            "all allocated frames need an associated page info, {:?} didn't",
            new_frame
        )
    });
    assert_eq!(page_info.refcount(), RefCount::Zero);
    page_info
        .refcount
        .store(init_rc.to_raw(), Ordering::Relaxed);

    Ok(new_frame)
}
