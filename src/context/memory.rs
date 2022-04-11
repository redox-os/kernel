use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use core::borrow::Borrow;
use core::cmp::{self, Eq, Ordering, PartialEq, PartialOrd};
use core::fmt::{self, Debug};
use core::intrinsics;
use core::ops::{Deref, DerefMut};
use spin::Mutex;
use syscall::{
    flag::MapFlags,
    error::*,
};

use crate::arch::paging::PAGE_SIZE;
use crate::context::file::FileDescriptor;
use crate::ipi::{ipi, IpiKind, IpiTarget};
use crate::memory::Frame;
use crate::paging::mapper::PageFlushAll;
use crate::paging::{ActivePageTable, InactivePageTable, Page, PageFlags, PageIter, PhysicalAddress, RmmA, VirtualAddress};

/// Round down to the nearest multiple of page size
pub fn round_down_pages(number: usize) -> usize {
    number - number % PAGE_SIZE
}
/// Round up to the nearest multiple of page size
pub fn round_up_pages(number: usize) -> usize {
    round_down_pages(number + PAGE_SIZE - 1)
}

pub fn page_flags(flags: MapFlags) -> PageFlags<RmmA> {
    PageFlags::new()
        .user(true)
        .execute(flags.contains(MapFlags::PROT_EXEC))
        .write(flags.contains(MapFlags::PROT_WRITE))
        //TODO: PROT_READ
}

pub struct UnmapResult {
    pub file_desc: Option<GrantFileRef>,
}
impl Drop for UnmapResult {
    fn drop(&mut self) {
        if let Some(fd) = self.file_desc.take() {
            let _ = fd.desc.close();
        }
    }
}

#[derive(Debug, Default)]
pub struct UserGrants {
    pub inner: BTreeSet<Grant>,
    //TODO: technically VirtualAddress is from a scheme's context!
    pub funmap: BTreeMap<Region, VirtualAddress>,
}

impl UserGrants {
    /// Returns the grant, if any, which occupies the specified address
    pub fn contains(&self, address: VirtualAddress) -> Option<&Grant> {
        let byte = Region::byte(address);
        self.inner
            .range(..=byte)
            .next_back()
            .filter(|existing| existing.occupies(byte))
    }
    /// Returns an iterator over all grants that occupy some part of the
    /// requested region
    pub fn conflicts<'a>(&'a self, requested: Region) -> impl Iterator<Item = &'a Grant> + 'a {
        let start = self.contains(requested.start_address());
        let start_region = start.map(Region::from).unwrap_or(requested);
        self
            .inner
            .range(start_region..)
            .take_while(move |region| !region.intersect(requested).is_empty())
    }
    /// Return a free region with the specified size
    pub fn find_free(&self, size: usize) -> Region {
        // Get last used region
        let last = self.inner.iter().next_back().map(Region::from).unwrap_or(Region::new(VirtualAddress::new(0), 0));
        // At the earliest, start at grant offset
        let address = cmp::max(last.end_address().data(), crate::USER_GRANT_OFFSET);
        // Create new region
        Region::new(VirtualAddress::new(address), size)
    }
    /// Return a free region, respecting the user's hinted address and flags. Address may be null.
    pub fn find_free_at(&mut self, address: VirtualAddress, size: usize, flags: MapFlags) -> Result<Region> {
        if address == VirtualAddress::new(0) {
            // Free hands!
            return Ok(self.find_free(size));
        }

        // The user wished to have this region...
        let mut requested = Region::new(address, size);

        if
            requested.end_address().data() >= crate::PML4_SIZE * 256 // There are 256 PML4 entries reserved for userspace
            && address.data() % PAGE_SIZE != 0
        {
            // ... but it was invalid
            return Err(Error::new(EINVAL));
        }

        if let Some(grant) = self.contains(requested.start_address()) {
            // ... but it already exists

            if flags.contains(MapFlags::MAP_FIXED_NOREPLACE) {
                println!("grant: conflicts with: {:#x} - {:#x}", grant.start_address().data(), grant.end_address().data());
                return Err(Error::new(EEXIST));
            } else if flags.contains(MapFlags::MAP_FIXED) {
                // TODO: Overwrite existing grant
                return Err(Error::new(EOPNOTSUPP));
            } else {
                // TODO: Find grant close to requested address?
                requested = self.find_free(requested.size());
            }
        }

        Ok(requested)
    }
}
impl Deref for UserGrants {
    type Target = BTreeSet<Grant>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for UserGrants {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Clone, Copy)]
pub struct Region {
    start: VirtualAddress,
    size: usize,
}
impl Region {
    /// Create a new region with the given size
    pub fn new(start: VirtualAddress, size: usize) -> Self {
        Self { start, size }
    }

    /// Create a new region spanning exactly one byte
    pub fn byte(address: VirtualAddress) -> Self {
        Self::new(address, 1)
    }

    /// Create a new region spanning between the start and end address
    /// (exclusive end)
    pub fn between(start: VirtualAddress, end: VirtualAddress) -> Self {
        Self::new(
            start,
            end.data().saturating_sub(start.data()),
        )
    }

    /// Return the part of the specified region that intersects with self.
    pub fn intersect(&self, other: Self) -> Self {
        Self::between(
            cmp::max(self.start_address(), other.start_address()),
            cmp::min(self.end_address(), other.end_address()),
        )
    }

    /// Get the start address of the region
    pub fn start_address(&self) -> VirtualAddress {
        self.start
    }
    /// Set the start address of the region
    pub fn set_start_address(&mut self, start: VirtualAddress) {
        self.start = start;
    }

    /// Get the last address in the region (inclusive end)
    pub fn final_address(&self) -> VirtualAddress {
        VirtualAddress::new(self.start.data() + self.size - 1)
    }

    /// Get the start address of the next region (exclusive end)
    pub fn end_address(&self) -> VirtualAddress {
        VirtualAddress::new(self.start.data() + self.size)
    }

    /// Return the exact size of the region
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return true if the size of this region is zero. Grants with such a
    /// region should never exist.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Set the exact size of the region
    pub fn set_size(&mut self, size: usize) {
        self.size = size;
    }

    /// Round region up to nearest page size
    pub fn round(self) -> Self {
        Self {
            size: round_up_pages(self.size),
            ..self
        }
    }

    /// Return the size of the grant in multiples of the page size
    pub fn full_size(&self) -> usize {
        self.round().size()
    }

    /// Returns true if the address is within the regions's requested range
    pub fn collides(&self, other: Self) -> bool {
        self.start_address() <= other.start_address() && other.end_address().data() - self.start_address().data() < self.size()
    }
    /// Returns true if the address is within the regions's actual range (so,
    /// rounded up to the page size)
    pub fn occupies(&self, other: Self) -> bool {
        self.round().collides(other)
    }

    /// Return all pages containing a chunk of the region
    pub fn pages(&self) -> PageIter {
        Page::range_inclusive(
            Page::containing_address(self.start_address()),
            Page::containing_address(self.end_address())
        )
    }

    /// Returns the region from the start of self until the start of the specified region.
    ///
    /// # Panics
    ///
    /// Panics if the given region starts before self
    pub fn before(self, region: Self) -> Option<Self> {
        assert!(self.start_address() <= region.start_address());
        Some(Self::between(
            self.start_address(),
            region.start_address(),
        )).filter(|reg| !reg.is_empty())
    }

    /// Returns the region from the end of the given region until the end of self.
    ///
    /// # Panics
    ///
    /// Panics if self ends before the given region
    pub fn after(self, region: Self) -> Option<Self> {
        assert!(region.end_address() <= self.end_address());
        Some(Self::between(
            region.end_address(),
            self.end_address(),
        )).filter(|reg| !reg.is_empty())
    }

    /// Re-base address that lives inside this region, onto a new base region
    pub fn rebase(self, new_base: Self, address: VirtualAddress) -> VirtualAddress {
        let offset = address.data() - self.start_address().data();
        let new_start = new_base.start_address().data() + offset;
        VirtualAddress::new(new_start)
    }
}

impl PartialEq for Region {
    fn eq(&self, other: &Self) -> bool {
        self.start.eq(&other.start)
    }
}
impl Eq for Region {}

impl PartialOrd for Region {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.start.partial_cmp(&other.start)
    }
}
impl Ord for Region {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start.cmp(&other.start)
    }
}

impl Debug for Region {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}..{:#x} ({:#x} long)", self.start_address().data(), self.end_address().data(), self.size())
    }
}


impl<'a> From<&'a Grant> for Region {
    fn from(source: &'a Grant) -> Self {
        source.region
    }
}


#[derive(Debug)]
pub struct Grant {
    region: Region,
    flags: PageFlags<RmmA>,
    mapped: bool,
    owned: bool,
    //TODO: This is probably a very heavy way to keep track of fmap'd files, perhaps move to the context?
    pub desc_opt: Option<GrantFileRef>,
}
#[derive(Clone, Debug)]
pub struct GrantFileRef {
    pub desc: FileDescriptor,
    pub offset: usize,
    // TODO: Can the flags maybe be stored together with the page flags. Should some flags be kept,
    // and others discarded when re-fmapping on clone?
    pub flags: MapFlags,
}

impl Grant {
    pub fn is_owned(&self) -> bool {
        self.owned
    }

    pub fn region(&self) -> &Region {
        &self.region
    }

    /// Get a mutable reference to the region. This is unsafe, because a bad
    /// region could lead to the wrong addresses being unmapped.
    unsafe fn region_mut(&mut self) -> &mut Region {
        &mut self.region
    }

    pub fn physmap(from: PhysicalAddress, to: VirtualAddress, size: usize, flags: PageFlags<RmmA>) -> Grant {
        let mut active_table = unsafe { ActivePageTable::new(to.kind()) };

        let flush_all = PageFlushAll::new();

        let start_page = Page::containing_address(to);
        let end_page = Page::containing_address(VirtualAddress::new(to.data() + size - 1));
        for page in Page::range_inclusive(start_page, end_page) {
            let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().data() - to.data() + from.data()));
            let result = active_table.map_to(page, frame, flags);
            flush_all.consume(result);
        }

        flush_all.flush();

        Grant {
            region: Region {
                start: to,
                size,
            },
            flags,
            mapped: true,
            owned: false,
            desc_opt: None,
        }
    }

    pub fn map(to: VirtualAddress, size: usize, flags: PageFlags<RmmA>) -> Grant {
        let mut active_table = unsafe { ActivePageTable::new(to.kind()) };

        let flush_all = PageFlushAll::new();

        let start_page = Page::containing_address(to);
        let end_page = Page::containing_address(VirtualAddress::new(to.data() + size - 1));
        for page in Page::range_inclusive(start_page, end_page) {
            let result = active_table
                .map(page, flags)
                .expect("TODO: handle ENOMEM in Grant::map");
            flush_all.consume(result);
        }

        flush_all.flush();

        Grant {
            region: Region {
                start: to,
                size,
            },
            flags,
            mapped: true,
            owned: true,
            desc_opt: None,
        }
    }

    pub fn map_inactive(src: VirtualAddress, dst: VirtualAddress, size: usize, flags: PageFlags<RmmA>, desc_opt: Option<GrantFileRef>, inactive_table: &mut InactivePageTable) -> Grant {
        let active_table = unsafe { ActivePageTable::new(src.kind()) };
        let mut inactive_mapper = inactive_table.mapper();

        let src_start_page = Page::containing_address(src);
        let src_end_page = Page::containing_address(VirtualAddress::new(src.data() + size - 1));
        let src_range = Page::range_inclusive(src_start_page, src_end_page);

        let dst_start_page = Page::containing_address(dst);
        let dst_end_page = Page::containing_address(VirtualAddress::new(dst.data() + size - 1));
        let dst_range = Page::range_inclusive(dst_start_page, dst_end_page);

        for (src_page, dst_page) in src_range.zip(dst_range) {
            let frame = active_table.translate_page(src_page).expect("grant references unmapped memory");

            let inactive_flush = inactive_mapper.map_to(dst_page, frame, flags);
            // Ignore result due to mapping on inactive table
            unsafe { inactive_flush.ignore(); }
        }

        ipi(IpiKind::Tlb, IpiTarget::Other);

        Grant {
            region: Region {
                start: dst,
                size,
            },
            flags,
            mapped: true,
            owned: false,
            desc_opt,
        }
    }

    /// This function should only be used in clone!
    pub fn secret_clone(&self, new_start: VirtualAddress) -> Grant {
        assert!(self.mapped);

        let mut active_table = unsafe { ActivePageTable::new(new_start.kind()) };

        let flush_all = PageFlushAll::new();

        let start_page = Page::containing_address(self.region.start);
        let end_page = Page::containing_address(VirtualAddress::new(self.region.start.data() + self.region.size - 1));
        for page in Page::range_inclusive(start_page, end_page) {
            //TODO: One function to do both?
            let flags = active_table.translate_page_flags(page).expect("grant references unmapped memory");
            let frame = active_table.translate_page(page).expect("grant references unmapped memory");

            let new_page = Page::containing_address(VirtualAddress::new(page.start_address().data() - self.region.start.data() + new_start.data()));
            if self.owned {
                let result = active_table.map(new_page, PageFlags::new().write(true))
                    .expect("TODO: handle ENOMEM in Grant::secret_clone");
                flush_all.consume(result);
            } else {
                let result = active_table.map_to(new_page, frame, flags);
                flush_all.consume(result);
            }
        }

        flush_all.flush();

        if self.owned {
            unsafe {
                intrinsics::copy(self.region.start.data() as *const u8, new_start.data() as *mut u8, self.region.size);
            }

            let flush_all = PageFlushAll::new();

            for page in Page::range_inclusive(start_page, end_page) {
                //TODO: One function to do both?
                let flags = active_table.translate_page_flags(page).expect("grant references unmapped memory");

                let new_page = Page::containing_address(VirtualAddress::new(page.start_address().data() - self.region.start.data() + new_start.data()));
                let result = active_table.remap(new_page, flags);
                flush_all.consume(result);
            }

            flush_all.flush();
        }

        Grant {
            region: Region {
                start: new_start,
                size: self.region.size,
            },
            flags: self.flags,
            mapped: true,
            owned: self.owned,
            desc_opt: self.desc_opt.clone()
        }
    }

    pub fn move_to(&mut self, new_start: VirtualAddress, new_table: &mut InactivePageTable) {
        assert!(self.mapped);

        let mut active_table = unsafe { ActivePageTable::new(new_start.kind()) };

        let flush_all = PageFlushAll::new();

        let start_page = Page::containing_address(self.region.start);
        let end_page = Page::containing_address(VirtualAddress::new(self.region.start.data() + self.region.size - 1));
        for page in Page::range_inclusive(start_page, end_page) {
            //TODO: One function to do both?
            let flags = active_table.translate_page_flags(page).expect("grant references unmapped memory");
            let (result, frame) = active_table.unmap_return(page, false);
            flush_all.consume(result);

            let new_page = Page::containing_address(VirtualAddress::new(page.start_address().data() - self.region.start.data() + new_start.data()));
            let result = new_table.mapper().map_to(new_page, frame, flags);
            // Ignore result due to mapping on inactive table
            unsafe { result.ignore(); }
        }

        flush_all.flush();

        self.region.start = new_start;
    }

    pub fn flags(&self) -> PageFlags<RmmA> {
        self.flags
    }

    pub fn unmap(mut self) -> UnmapResult {
        assert!(self.mapped);

        let mut active_table = unsafe { ActivePageTable::new(self.start_address().kind()) };


        let flush_all = PageFlushAll::new();

        let start_page = Page::containing_address(self.start_address());
        let end_page = Page::containing_address(self.final_address());
        for page in Page::range_inclusive(start_page, end_page) {
            let (result, frame) = active_table.unmap_return(page, false);
            if self.owned {
                //TODO: make sure this frame can be safely freed, physical use counter
                crate::memory::deallocate_frames(frame, 1);
            }
            flush_all.consume(result);
        }

        flush_all.flush();

        self.mapped = false;

        // TODO: This imposes a large cost on unmapping, but that cost cannot be avoided without modifying fmap and funmap
        UnmapResult { file_desc: self.desc_opt.take() }
    }

    pub fn unmap_inactive(mut self, new_table: &mut InactivePageTable) -> UnmapResult {
        assert!(self.mapped);

        let start_page = Page::containing_address(self.start_address());
        let end_page = Page::containing_address(self.final_address());
        for page in Page::range_inclusive(start_page, end_page) {
            let (result, frame) = new_table.mapper().unmap_return(page, false);
            if self.owned {
                //TODO: make sure this frame can be safely freed, physical use counter
                crate::memory::deallocate_frames(frame, 1);
            }
            // This is not the active table, so the flush can be ignored
            unsafe { result.ignore(); }
        }

        ipi(IpiKind::Tlb, IpiTarget::Other);

        self.mapped = false;

        // TODO: This imposes a large cost on unmapping, but that cost cannot be avoided without modifying fmap and funmap
        UnmapResult { file_desc: self.desc_opt.take() }
    }

    /// Extract out a region into a separate grant. The return value is as
    /// follows: (before, new split, after). Before and after may be `None`,
    /// which occurs when the split off region is at the start or end of the
    /// page respectively.
    ///
    /// # Panics
    ///
    /// Panics if the start or end addresses of the region is not aligned to the
    /// page size. To round up the size to the nearest page size, use `.round()`
    /// on the region.
    ///
    /// Also panics if the given region isn't completely contained within the
    /// grant. Use `grant.intersect` to find a sub-region that works.
    pub fn extract(mut self, region: Region) -> Option<(Option<Grant>, Grant, Option<Grant>)> {
        assert_eq!(region.start_address().data() % PAGE_SIZE, 0, "split_out must be called on page-size aligned start address");
        assert_eq!(region.size() % PAGE_SIZE, 0, "split_out must be called on page-size aligned end address");

        let before_grant = self.before(region).map(|region| Grant {
            region,
            flags: self.flags,
            mapped: self.mapped,
            owned: self.owned,
            desc_opt: self.desc_opt.clone(),
        });
        let after_grant = self.after(region).map(|region| Grant {
            region,
            flags: self.flags,
            mapped: self.mapped,
            owned: self.owned,
            desc_opt: self.desc_opt.clone(),
        });

        unsafe {
            *self.region_mut() = region;
        }

        Some((before_grant, self, after_grant))
    }
}

impl Deref for Grant {
    type Target = Region;
    fn deref(&self) -> &Self::Target {
        &self.region
    }
}

impl PartialOrd for Grant {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.region.partial_cmp(&other.region)
    }
}
impl Ord for Grant {
    fn cmp(&self, other: &Self) -> Ordering {
        self.region.cmp(&other.region)
    }
}
impl PartialEq for Grant {
    fn eq(&self, other: &Self) -> bool {
        self.region.eq(&other.region)
    }
}
impl Eq for Grant {}

impl Borrow<Region> for Grant {
    fn borrow(&self) -> &Region {
        &self.region
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        assert!(!self.mapped, "Grant dropped while still mapped");
    }
}

#[derive(Clone, Debug)]
pub enum SharedMemory {
    Owned(Arc<Mutex<Memory>>),
    Borrowed(Weak<Mutex<Memory>>)
}

impl SharedMemory {
    pub fn with<F, T>(&self, f: F) -> T where F: FnOnce(&mut Memory) -> T {
        match *self {
            SharedMemory::Owned(ref memory_lock) => {
                let mut memory = memory_lock.lock();
                f(&mut *memory)
            },
            SharedMemory::Borrowed(ref memory_weak) => {
                let memory_lock = memory_weak.upgrade().expect("SharedMemory::Borrowed no longer valid");
                let mut memory = memory_lock.lock();
                f(&mut *memory)
            }
        }
    }

    pub fn borrow(&self) -> SharedMemory {
        match *self {
            SharedMemory::Owned(ref memory_lock) => SharedMemory::Borrowed(Arc::downgrade(memory_lock)),
            SharedMemory::Borrowed(ref memory_lock) => SharedMemory::Borrowed(memory_lock.clone())
        }
    }
}

#[derive(Debug)]
pub struct Memory {
    start: VirtualAddress,
    size: usize,
    flags: PageFlags<RmmA>,
}

impl Memory {
    pub fn new(start: VirtualAddress, size: usize, flags: PageFlags<RmmA>, clear: bool) -> Self {
        let mut memory = Memory {
            start,
            size,
            flags,
        };

        memory.map(clear);

        memory
    }

    pub fn to_shared(self) -> SharedMemory {
        SharedMemory::Owned(Arc::new(Mutex::new(self)))
    }

    pub fn start_address(&self) -> VirtualAddress {
        self.start
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn flags(&self) -> PageFlags<RmmA> {
        self.flags
    }

    pub fn pages(&self) -> PageIter {
        let start_page = Page::containing_address(self.start);
        let end_page = Page::containing_address(VirtualAddress::new(self.start.data() + self.size - 1));
        Page::range_inclusive(start_page, end_page)
    }

    fn map(&mut self, clear: bool) {
        let mut active_table = unsafe { ActivePageTable::new(self.start.kind()) };

        let flush_all = PageFlushAll::new();

        for page in self.pages() {
            let result = active_table
                .map(page, self.flags)
                .expect("TODO: handle ENOMEM in Memory::map");
            flush_all.consume(result);
        }

        flush_all.flush();

        if clear {
            assert!(self.flags.has_write());
            unsafe {
                intrinsics::write_bytes(self.start_address().data() as *mut u8, 0, self.size);
            }
        }
    }

    fn unmap(&mut self) {
        let mut active_table = unsafe { ActivePageTable::new(self.start.kind()) };

        let flush_all = PageFlushAll::new();

        for page in self.pages() {
            let result = active_table.unmap(page);
            flush_all.consume(result);
        }

        flush_all.flush();
    }

    /// A complicated operation to move a piece of memory to a new page table
    /// It also allows for changing the address at the same time
    pub fn move_to(&mut self, new_start: VirtualAddress, new_table: &mut InactivePageTable) {
        let mut inactive_mapper = new_table.mapper();

        let mut active_table = unsafe { ActivePageTable::new(new_start.kind()) };

        let flush_all = PageFlushAll::new();

        for page in self.pages() {
            let (result, frame) = active_table.unmap_return(page, false);
            flush_all.consume(result);

            let new_page = Page::containing_address(VirtualAddress::new(page.start_address().data() - self.start.data() + new_start.data()));
            let result = inactive_mapper.map_to(new_page, frame, self.flags);
            // This is not the active table, so the flush can be ignored
            unsafe { result.ignore(); }
        }

        flush_all.flush();

        self.start = new_start;
    }

    pub fn remap(&mut self, new_flags: PageFlags<RmmA>) {
        let mut active_table = unsafe { ActivePageTable::new(self.start.kind()) };

        let flush_all = PageFlushAll::new();

        for page in self.pages() {
            let result = active_table.remap(page, new_flags);
            flush_all.consume(result);
        }

        flush_all.flush();

        self.flags = new_flags;
    }

    pub fn resize(&mut self, new_size: usize, clear: bool) {
        let mut active_table = unsafe { ActivePageTable::new(self.start.kind()) };

        //TODO: Calculate page changes to minimize operations
        if new_size > self.size {
            let flush_all = PageFlushAll::new();

            let start_page = Page::containing_address(VirtualAddress::new(self.start.data() + self.size));
            let end_page = Page::containing_address(VirtualAddress::new(self.start.data() + new_size - 1));
            for page in Page::range_inclusive(start_page, end_page) {
                if active_table.translate_page(page).is_none() {
                    let result = active_table
                        .map(page, self.flags)
                        .expect("TODO: Handle OOM in Memory::resize");
                    flush_all.consume(result);
                }
            }

            flush_all.flush();

            if clear {
                unsafe {
                    intrinsics::write_bytes((self.start.data() + self.size) as *mut u8, 0, new_size - self.size);
                }
            }
        } else if new_size < self.size {
            let flush_all = PageFlushAll::new();

            let start_page = Page::containing_address(VirtualAddress::new(self.start.data() + new_size));
            let end_page = Page::containing_address(VirtualAddress::new(self.start.data() + self.size - 1));
            for page in Page::range_inclusive(start_page, end_page) {
                if active_table.translate_page(page).is_some() {
                    let result = active_table.unmap(page);
                    flush_all.consume(result);
                }
            }

            flush_all.flush();
        }

        self.size = new_size;
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        self.unmap();
    }
}

pub const DANGLING: usize = 1 << (usize::BITS - 2);

#[cfg(tests)]
mod tests {
    // TODO: Get these tests working
    #[test]
    fn region_collides() {
        assert!(Region::new(0, 2).collides(Region::new(0, 1)));
        assert!(Region::new(0, 2).collides(Region::new(1, 1)));
        assert!(!Region::new(0, 2).collides(Region::new(2, 1)));
        assert!(!Region::new(0, 2).collides(Region::new(3, 1)));
    }
}
