use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use core::borrow::Borrow;
use core::cmp::{self, Eq, Ordering, PartialEq, PartialOrd};
use core::fmt::{self, Debug};
use core::intrinsics;
use core::ops::Deref;
use core::sync::atomic;
use spin::{Mutex, RwLock};
use syscall::{
    flag::MapFlags,
    error::*,
};
use rmm::Arch as _;

use crate::arch::paging::PAGE_SIZE;
use crate::context::file::FileDescriptor;
use crate::memory::Frame;
use crate::paging::mapper::{Flusher, InactiveFlusher, Mapper, PageFlushAll};
use crate::paging::{ActivePageTable, InactivePageTable, Page, PageFlags, PageIter, PhysicalAddress, RmmA, TableKind, VirtualAddress};

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

int_like!(PtId, usize);

static ADDRSPACES: RwLock<BTreeMap<PtId, Arc<RwLock<AddrSpace>>>> = RwLock::new(BTreeMap::new());
static NEXT_PTID: atomic::AtomicUsize = atomic::AtomicUsize::new(1);

pub fn new_addrspace() -> Result<(PtId, Arc<RwLock<AddrSpace>>)> {
    let id = PtId::from(NEXT_PTID.fetch_add(1, atomic::Ordering::Relaxed));
    let arc = Arc::try_new(RwLock::new(AddrSpace::new(id)?)).map_err(|_| Error::new(ENOMEM))?;
    ADDRSPACES.write().insert(id, Arc::clone(&arc));
    Ok((id, arc))
}
pub fn addrspace(id: PtId) -> Option<Arc<RwLock<AddrSpace>>> {
    ADDRSPACES.read().get(&id).map(Arc::clone)
}

#[derive(Debug)]
pub struct AddrSpace {
    pub frame: Tables,
    pub grants: UserGrants,
    pub id: PtId,
}
impl AddrSpace {
    /// Attempt to clone an existing address space so that all mappings are copied (CoW).
    // TODO: Actually use CoW!
    pub fn try_clone(&self) -> Result<(PtId, Arc<RwLock<Self>>)> {
        let (id, mut new) = new_addrspace()?;

        // TODO: Abstract away this.
        let (mut inactive, mut active);

        // TODO: aarch64
        let mut this_mapper = if self.frame.utable.start_address().data() == unsafe { x86::controlregs::cr3() } as usize {
            active = unsafe { ActivePageTable::new(rmm::TableKind::User) };
            active.mapper()
        } else {
            inactive = unsafe { InactivePageTable::from_address(self.frame.utable.start_address().data()) };
            inactive.mapper()
        };
        let mut new_mapper = unsafe { InactivePageTable::from_address(new.read().frame.utable.start_address().data()) };

        for grant in self.grants.iter() {
            // TODO: Fail if there are borrowed grants, rather than simply ignoring them?
            if !grant.is_owned() { continue; }

            let new_grant = Grant::zeroed(Page::containing_address(grant.start_address()), grant.size() / PAGE_SIZE, grant.flags(), &mut new_mapper.mapper(), ())?;

            for page in new_grant.pages() {
                // FIXME: ENOMEM is wrong here, it cannot fail.
                let current_frame = this_mapper.translate_page(page).ok_or(Error::new(ENOMEM))?.start_address().data() as *const u8;
                let new_frame = new_mapper.mapper().translate_page(page).ok_or(Error::new(ENOMEM))?.start_address().data() as *mut u8;

                // TODO: Replace this with CoW
                unsafe {
                    new_frame.copy_from_nonoverlapping(current_frame, PAGE_SIZE);
                }
            }

            new.write().grants.insert(new_grant);
        }
        Ok((id, new))
    }
    pub fn new(id: PtId) -> Result<Self> {
        Ok(Self {
            grants: UserGrants::new(),
            frame: setup_new_utable()?,
            id,
        })
    }
}

#[derive(Debug)]
pub struct UserGrants {
    inner: BTreeSet<Grant>,
    holes: BTreeMap<VirtualAddress, usize>,
    // TODO: Would an additional map ordered by (size,start) to allow for O(log n) allocations be
    // beneficial?

    //TODO: technically VirtualAddress is from a scheme's context!
    pub funmap: BTreeMap<Region, VirtualAddress>,
}

impl Default for UserGrants {
    fn default() -> Self {
        Self::new()
    }
}

impl UserGrants {
    pub fn new() -> Self {
        Self {
            inner: BTreeSet::new(),
            holes: core::iter::once((VirtualAddress::new(0), crate::USER_END_OFFSET)).collect::<BTreeMap<_, _>>(),
            funmap: BTreeMap::new(),
        }
    }
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
    // TODO: Alignment (x86_64: 4 KiB, 2 MiB, or 1 GiB).
    pub fn find_free(&self, size: usize) -> Option<Region> {
        // Get first available hole, but do reserve the page starting from zero as most compiled
        // languages cannot handle null pointers safely even if they point to valid memory. If an
        // application absolutely needs to map the 0th page, they will have to do so explicitly via
        // MAP_FIXED/MAP_FIXED_NOREPLACE.
        // TODO: Allow explicitly allocating guard pages?

        let (hole_start, hole_size) = self.holes.iter().find(|(hole_offset, hole_size)| size <= if hole_offset.data() == 0 { hole_size.saturating_sub(PAGE_SIZE) } else { **hole_size })?;
        // Create new region
        Some(Region::new(VirtualAddress::new(cmp::max(hole_start.data(), PAGE_SIZE)), size))
    }
    /// Return a free region, respecting the user's hinted address and flags. Address may be null.
    pub fn find_free_at(&mut self, address: VirtualAddress, size: usize, flags: MapFlags) -> Result<Region> {
        if address == VirtualAddress::new(0) {
            // Free hands!
            return self.find_free(size).ok_or(Error::new(ENOMEM));
        }

        // The user wished to have this region...
        let mut requested = Region::new(address, size);

        if
            requested.end_address().data() > crate::USER_END_OFFSET
            || address.data() % PAGE_SIZE != 0
        {
            // ... but it was invalid
            return Err(Error::new(EINVAL));
        }

        if let Some(grant) = self.contains(requested.start_address()) {
            // ... but it already exists

            if flags.contains(MapFlags::MAP_FIXED_NOREPLACE) {
                println!("grant: {:#x} conflicts with: {:#x} - {:#x}", address.data(), grant.start_address().data(), grant.end_address().data());
                return Err(Error::new(EEXIST));
            } else if flags.contains(MapFlags::MAP_FIXED) {
                // TODO: Overwrite existing grant
                return Err(Error::new(EOPNOTSUPP));
            } else {
                // TODO: Find grant close to requested address?
                requested = self.find_free(requested.size()).ok_or(Error::new(ENOMEM))?;
            }
        }

        Ok(requested)
    }
    fn reserve(&mut self, grant: &Region) {
        let previous_hole = self.holes.range_mut(..grant.start_address()).next_back();

        if let Some((hole_offset, hole_size)) = previous_hole {
            let prev_hole_end = hole_offset.data() + *hole_size;

            // Note that prev_hole_end cannot exactly equal grant.start_address, since that would
            // imply there is another grant at that position already, as it would otherwise have
            // been larger.

            if prev_hole_end > grant.start_address().data() {
                // hole_offset must be below (but never equal to) the start address due to the
                // `..grant.start_address()` limit; hence, all we have to do is to shrink the
                // previous offset.
                *hole_size = grant.start_address().data() - hole_offset.data();
            }
            if prev_hole_end > grant.end_address().data() {
                // The grant is splitting this hole in two, so insert the new one at the end.
                self.holes.insert(grant.end_address(), prev_hole_end - grant.end_address().data());
            }
        }

        // Next hole
        if let Some(hole_size) = self.holes.remove(&grant.start_address()) {
            let remainder = hole_size - grant.size();
            if remainder > 0 {
                self.holes.insert(grant.end_address(), remainder);
            }
        }
    }
    fn unreserve(holes: &mut BTreeMap<VirtualAddress, usize>, grant: &Region) {
        // The size of any possible hole directly after the to-be-freed region.
        let exactly_after_size = holes.remove(&grant.end_address());

        // There was a range that began exactly prior to the to-be-freed region, so simply
        // increment the size such that it occupies the grant too. If in additional there was a
        // grant directly after the grant, include it too in the size.
        if let Some((hole_offset, hole_size)) = holes.range_mut(..grant.start_address()).next_back().filter(|(offset, size)| offset.data() + **size == grant.start_address().data()) {
            *hole_size = grant.end_address().data() - hole_offset.data() + exactly_after_size.unwrap_or(0);
        } else {
            // There was no free region directly before the to-be-freed region, however will
            // now unconditionally insert a new free region where the grant was, and add that extra
            // size if there was something after it.
            holes.insert(grant.start_address(), grant.size() + exactly_after_size.unwrap_or(0));
        }
    }
    pub fn insert(&mut self, grant: Grant) {
        self.reserve(&grant);
        self.inner.insert(grant);
    }
    pub fn remove(&mut self, region: &Region) -> bool {
        self.take(region).is_some()
    }
    pub fn take(&mut self, region: &Region) -> Option<Grant> {
        let grant = self.inner.take(region)?;
        Self::unreserve(&mut self.holes, region);
        Some(grant)
    }
    pub fn iter(&self) -> impl Iterator<Item = &Grant> + '_ {
        self.inner.iter()
    }
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
    pub fn into_iter(self) -> impl Iterator<Item = Grant> {
        self.inner.into_iter()
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
        Page::range_exclusive(
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

        let mut flush_all = PageFlushAll::new();

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
    pub fn zeroed(dst: Page, page_count: usize, flags: PageFlags<RmmA>, mapper: &mut Mapper, mut flusher: impl Flusher<RmmA>) -> Result<Grant> {
        for page in Page::range_exclusive(dst, dst.next_by(page_count)) {
            let flush = mapper.map(page, flags).map_err(|_| Error::new(ENOMEM))?;
            flusher.consume(flush);
        }
        Ok(Grant { region: Region { start: dst.start_address(), size: page_count * PAGE_SIZE }, flags, mapped: true, owned: true, desc_opt: None })
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

    pub fn flags(&self) -> PageFlags<RmmA> {
        self.flags
    }

    pub fn unmap(mut self, mapper: &mut Mapper, mut flusher: impl Flusher<RmmA>) -> UnmapResult {
        assert!(self.mapped);

        for page in self.pages() {
            let (result, frame) = mapper.unmap_return(page, false);
            if self.owned {
                //TODO: make sure this frame can be safely freed, physical use counter
                crate::memory::deallocate_frames(frame, 1);
            }
            flusher.consume(result);
        }

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

pub const DANGLING: usize = 1 << (usize::BITS - 2);

#[derive(Debug)]
pub struct Tables {
    #[cfg(target_arch = "aarch64")]
    pub ktable: Frame,

    pub utable: Frame,
}

impl Drop for Tables {
    fn drop(&mut self) {
        use crate::memory::deallocate_frames;
        deallocate_frames(Frame::containing_address(PhysicalAddress::new(self.utable.start_address().data())), 1);

        #[cfg(target_arch = "aarch64")]
        deallocate_frames(Frame::containing_address(PhysicalAddress::new(self.ktable.start_address().data())), 1);
    }
}

/// Allocates a new identically mapped ktable and empty utable (same memory on x86_64).
pub fn setup_new_utable() -> Result<Tables> {
    let mut new_utable = crate::memory::allocate_frames(1).ok_or(Error::new(ENOMEM))?;

    // TODO: There is only supposed to be one ktable, right? Use a global variable to store the
    // ktable (or access it from a control register) on architectures which have ktables, or obtain
    // it from *any* utable on architectures which do not.
    #[cfg(target_arch = "aarch64")]
    let new_ktable = crate::memory::allocate_frames(1).ok_or(Error::new(ENOMEM))?;

    let active_ktable = unsafe { ActivePageTable::new(TableKind::Kernel) };

    #[cfg(target_arch = "aarch64")]
    let ktable = &new_ktable;

    #[cfg(not(target_arch = "aarch64"))]
    let ktable = &new_utable;

    let mut new_mapper = unsafe { InactivePageTable::from_address(ktable.start_address().data()) };

    let mut copy_mapping = |p4_no| {
        let frame = active_ktable.p4()[p4_no].pointed_frame().expect("kernel image not mapped");
        let flags = active_ktable.p4()[p4_no].flags();

        new_mapper.mapper().p4_mut()[p4_no].set(frame, flags);
    };
    // TODO: Just copy all 256 mappings?

    // Copy kernel image mapping
    copy_mapping(crate::KERNEL_PML4);

    // Copy kernel heap mapping
    copy_mapping(crate::KERNEL_HEAP_PML4);

    // Copy physmap mapping
    copy_mapping(crate::PHYS_PML4);

    // Copy kernel percpu (similar to TLS) mapping.
    copy_mapping(crate::KERNEL_PERCPU_PML4);

    Ok(Tables {
        utable: new_utable,
        #[cfg(target_arch = "aarch64")]
        ktable: new_ktable,
    })
}


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
