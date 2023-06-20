use alloc::collections::BTreeMap;
use alloc::{sync::Arc, vec::Vec};
use core::cmp;
use core::fmt::Debug;
use core::num::NonZeroUsize;
use spin::{RwLock, RwLockWriteGuard};
use syscall::{
    flag::MapFlags,
    error::*,
};
use rmm::Arch as _;

use crate::arch::paging::PAGE_SIZE;
use crate::context::file::FileDescriptor;
use crate::memory::{Enomem, Frame};
use crate::paging::mapper::{Flusher, InactiveFlusher, PageFlushAll};
use crate::paging::{KernelMapper, Page, PageFlags, PageMapper, RmmA, TableKind, VirtualAddress};

pub const MMAP_MIN_DEFAULT: usize = PAGE_SIZE;

pub fn page_flags(flags: MapFlags) -> PageFlags<RmmA> {
    PageFlags::new()
        .user(true)
        .execute(flags.contains(MapFlags::PROT_EXEC))
        .write(flags.contains(MapFlags::PROT_WRITE))
        //TODO: PROT_READ
}
pub fn map_flags(page_flags: PageFlags<RmmA>) -> MapFlags {
    let mut flags = MapFlags::PROT_READ;
    if page_flags.has_write() { flags |= MapFlags::PROT_WRITE; }
    if page_flags.has_execute() { flags |= MapFlags::PROT_EXEC; }
    // TODO: MAP_SHARED/MAP_PRIVATE (requires that grants keep track of what they borrow and if
    // they borrow shared or CoW).
    flags
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

pub fn new_addrspace() -> Result<Arc<RwLock<AddrSpace>>> {
    Arc::try_new(RwLock::new(AddrSpace::new()?)).map_err(|_| Error::new(ENOMEM))
}

#[derive(Debug)]
pub struct AddrSpace {
    pub table: Table,
    pub grants: UserGrants,
    /// Lowest offset for mmap invocations where the user has not already specified the offset
    /// (using MAP_FIXED/MAP_FIXED_NOREPLACE). Cf. Linux's `/proc/sys/vm/mmap_min_addr`, but with
    /// the exception that we have a memory safe kernel which doesn't have to protect itself
    /// against null pointers, so fixed mmaps to address zero are still allowed.
    pub mmap_min: usize,
}
impl AddrSpace {
    pub fn current() -> Result<Arc<RwLock<Self>>> {
        Ok(Arc::clone(super::current()?.read().addr_space()?))
    }

    /// Attempt to clone an existing address space so that all mappings are copied (CoW).
    pub fn try_clone(&mut self) -> Result<Arc<RwLock<Self>>> {
        let mut new = new_addrspace()?;

        let new_guard = Arc::get_mut(&mut new)
            .expect("expected new address space Arc not to be aliased")
            .get_mut();

        let this_mapper = &mut self.table.utable;
        let new_mapper = &mut new_guard.table.utable;

        for (grant_base, grant_info) in self.grants.iter() {
            if grant_info.desc_opt.is_some() { continue; }

            let new_grant;

            // TODO: Replace this with CoW
            if grant_info.owned {
                new_grant = Grant::zeroed(grant_base, grant_info.page_count, grant_info.flags, new_mapper, ())?;

                for page in new_grant.span().pages().map(Page::start_address) {
                    let current_frame = unsafe { RmmA::phys_to_virt(this_mapper.translate(page).expect("grant containing unmapped pages").0) }.data() as *const u8;
                    let new_frame = unsafe { RmmA::phys_to_virt(new_mapper.translate(page).expect("grant containing unmapped pages").0) }.data() as *mut u8;

                    unsafe {
                        new_frame.copy_from_nonoverlapping(current_frame, PAGE_SIZE);
                    }
                }
            } else {
                // TODO: Remove reborrow? In that case, physmapped memory will need to either be
                // remapped when cloning, or be backed by a file descriptor (like
                // `memory:physical`).
                new_grant = Grant::reborrow(grant_base, grant_info, grant_base, this_mapper, new_mapper, ())?;
            }

            new_guard.grants.insert(new_grant);
        }
        Ok(new)
    }
    pub fn new() -> Result<Self> {
        Ok(Self {
            grants: UserGrants::new(),
            table: setup_new_utable()?,
            mmap_min: MMAP_MIN_DEFAULT,
        })
    }
    pub fn is_current(&self) -> bool {
        self.table.utable.is_current()
    }
    pub fn mprotect(&mut self, requested_span: PageSpan, flags: MapFlags) -> Result<()> {
        let (mut active, mut inactive);
        let mut flusher = if self.is_current() {
            active = PageFlushAll::new();
            &mut active as &mut dyn Flusher<RmmA>
        } else {
            inactive = InactiveFlusher::new();
            &mut inactive as &mut dyn Flusher<RmmA>
        };
        let mapper = &mut self.table.utable;

        // TODO: Remove allocation (might require BTreeMap::set_key or interior mutability).
        let regions = self.grants.conflicts(requested_span).map(|(base, info)| PageSpan::new(base, info.page_count)).collect::<Vec<_>>();

        for grant_span in regions {
            let grant = self.grants.remove(grant_span.base).expect("grant cannot magically disappear while we hold the lock!");
            let intersection = grant_span.intersection(requested_span);

            let (before, mut grant, after) = grant.extract(intersection).expect("failed to extract grant");

            if let Some(before) = before { self.grants.insert(before); }
            if let Some(after) = after { self.grants.insert(after); }

            if !grant.info.can_have_flags(flags) {
                self.grants.insert(grant);
                return Err(Error::new(EACCES));
            }

            let new_flags = grant.info.flags()
                // TODO: Require a capability in order to map executable memory?
                .execute(flags.contains(MapFlags::PROT_EXEC))
                .write(flags.contains(MapFlags::PROT_WRITE));

            // TODO: Allow enabling/disabling read access on architectures which allow it. On
            // x86_64 with protection keys (although only enforced by userspace), and AArch64 (I
            // think), execute-only memory is also supported.

            grant.remap(mapper, &mut flusher, new_flags);
            self.grants.insert(grant);
        }
        Ok(())
    }
    pub fn munmap(mut self: RwLockWriteGuard<'_, Self>, requested_span: PageSpan) {
        let mut notify_files = Vec::new();

        let mut flusher = PageFlushAll::new();

        // TODO: Allocating may even be wrong!
        let conflicting: Vec<PageSpan> = self.grants.conflicts(requested_span).map(|(base, info)| PageSpan::new(base, info.page_count)).collect();

        for conflict in conflicting {
            let grant = self.grants.remove(conflict.base).expect("conflicting region didn't exist");
            let intersection = conflict.intersection(requested_span);
            let (before, mut grant, after) = grant.extract(intersection).expect("conflicting region shared no common parts");

            // Notify scheme that holds grant
            if let Some(file_desc) = grant.info.desc_opt.take() {
                notify_files.push((file_desc, intersection));
            }

            // Keep untouched regions
            if let Some(before) = before {
                self.grants.insert(before);
            }
            if let Some(after) = after {
                self.grants.insert(after);
            }

            // Remove irrelevant region
            grant.unmap(&mut self.table.utable, &mut flusher);
        }
        drop(self);

        for (file_ref, intersection) in notify_files {
            let scheme_id = { file_ref.desc.description.read().scheme };

            let scheme = match crate::scheme::schemes().get(scheme_id) {
                Some(scheme) => Arc::clone(scheme),
                // One could argue that EBADFD could be returned here, but we have already unmapped
                // the memory.
                None => continue,
            };
            // Same here, we don't really care about errors when schemes respond to unmap events.
            // The caller wants the memory to be unmapped, period. When already unmapped, what
            // would we do with error codes anyway?
            let _ = scheme.funmap(intersection.base.start_address().data(), intersection.count * PAGE_SIZE);

            let _ = file_ref.desc.close();
        }
    }
    pub fn mmap(&mut self, page: Option<Page>, page_count: NonZeroUsize, flags: MapFlags, map: impl FnOnce(Page, PageFlags<RmmA>, &mut PageMapper, &mut dyn Flusher<RmmA>) -> Result<Grant>) -> Result<Page> {
        // Finally, the end of all "T0DO: Abstract with other grant creation"!
        let selected_span = self.grants.find_free_at(self.mmap_min, page, page_count.get(), flags)?;

        // TODO: Threads share address spaces, so not only the inactive flusher should be sending
        // out IPIs.
        let (mut active, mut inactive);
        let flusher = if self.is_current() {
            active = PageFlushAll::new();
            &mut active as &mut dyn Flusher<RmmA>
        } else {
            inactive = InactiveFlusher::new();
            &mut inactive as &mut dyn Flusher<RmmA>
        };

        self.grants.insert(map(selected_span.base, page_flags(flags), &mut self.table.utable, flusher)?);

        Ok(selected_span.base)
    }
}

#[derive(Debug)]
pub struct UserGrants {
    inner: BTreeMap<Page, GrantInfo>,
    holes: BTreeMap<VirtualAddress, usize>,
    // TODO: Would an additional map ordered by (size,start) to allow for O(log n) allocations be
    // beneficial?

    //TODO: technically VirtualAddress is from a scheme's context!
    pub funmap: BTreeMap<Page, (usize, Page)>,
}

#[derive(Clone, Copy)]
pub struct PageSpan {
    pub base: Page,
    pub count: usize,
}
impl PageSpan {
    pub fn new(base: Page, count: usize) -> Self {
        Self { base, count }
    }
    pub fn validate_nonempty(address: VirtualAddress, size: usize) -> Option<Self> {
        Self::validate(address, size).filter(|this| !this.is_empty())
    }
    pub fn validate(address: VirtualAddress, size: usize) -> Option<Self> {
        if address.data() % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 { return None; }
        if address.data().saturating_add(size) > crate::USER_END_OFFSET { return None; }

        Some(Self::new(Page::containing_address(address), size / PAGE_SIZE))
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn intersection(&self, with: PageSpan) -> PageSpan {
        Self::between(
            cmp::max(self.base, with.base),
            cmp::min(self.end(), with.end()),
        )
    }
    pub fn intersects(&self, with: PageSpan) -> bool {
        !self.intersection(with).is_empty()
    }
    pub fn contains(&self, page: Page) -> bool {
        self.intersects(Self::new(page, 1))
    }
    pub fn slice(&self, inner_span: PageSpan) -> (Option<PageSpan>, PageSpan, Option<PageSpan>) {
        (self.before(inner_span), inner_span, self.after(inner_span))
    }
    pub fn pages(self) -> impl Iterator<Item = Page> {
        (0..self.count).map(move |i| self.base.next_by(i))
    }

    pub fn end(&self) -> Page {
        self.base.next_by(self.count)
    }

    /// Returns the span from the start of self until the start of the specified span.
    pub fn before(self, span: Self) -> Option<Self> {
        assert!(self.base <= span.base);
        Some(Self::between(
            self.base,
            span.base,
        )).filter(|reg| !reg.is_empty())
    }

    /// Returns the span from the end of the given span until the end of self.
    pub fn after(self, span: Self) -> Option<Self> {
        assert!(span.end() <= self.end());
        Some(Self::between(
            span.end(),
            self.end(),
        )).filter(|reg| !reg.is_empty())
    }
    /// Returns the span between two pages, `[start, end)`, truncating to zero if end < start.
    pub fn between(start: Page, end: Page) -> Self {
        Self::new(
            start,
            end.start_address().data().saturating_sub(start.start_address().data()) / PAGE_SIZE,
        )
    }

    pub fn rebase(self, new_base: Self, page: Page) -> Page {
        let offset = page.offset_from(self.base);
        new_base.base.next_by(offset)
    }
}

impl Default for UserGrants {
    fn default() -> Self {
        Self::new()
    }
}
impl Debug for PageSpan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{:p}:{:p}, {} pages]", self.base.start_address().data() as *const u8, self.base.start_address().add(self.count * PAGE_SIZE - 1).data() as *const u8, self.count)
    }
}

impl UserGrants {
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
            holes: core::iter::once((VirtualAddress::new(0), crate::USER_END_OFFSET)).collect::<BTreeMap<_, _>>(),
            funmap: BTreeMap::new(),
        }
    }
    /// Returns the grant, if any, which occupies the specified page
    pub fn contains(&self, page: Page) -> Option<(Page, &GrantInfo)> {
        self.inner
            .range(..=page)
            .next_back()
            .filter(|(base, info)| (**base..base.next_by(info.page_count)).contains(&page))
            .map(|(base, info)| (*base, info))
    }
    /// Returns an iterator over all grants that occupy some part of the
    /// requested region
    pub fn conflicts(&self, span: PageSpan) -> impl Iterator<Item = (Page, &'_ GrantInfo)> + '_ {
        let start = self.contains(span.base);

        // If there is a grant that contains the base page, start searching at the base of that
        // grant, rather than the requested base here.
        let start_span = start.map(|(base, info)| PageSpan::new(base, info.page_count)).unwrap_or(span);

        self
            .inner
            .range(start_span.base..)
            .take_while(move |(base, info)| PageSpan::new(**base, info.page_count).intersects(span))
            .map(|(base, info)| (*base, info))
    }
    /// Return a free region with the specified size
    // TODO: Alignment (x86_64: 4 KiB, 2 MiB, or 1 GiB).
    pub fn find_free(&self, min: usize, page_count: usize) -> Option<PageSpan> {
        // Get first available hole, but do reserve the page starting from zero as most compiled
        // languages cannot handle null pointers safely even if they point to valid memory. If an
        // application absolutely needs to map the 0th page, they will have to do so explicitly via
        // MAP_FIXED/MAP_FIXED_NOREPLACE.
        // TODO: Allow explicitly allocating guard pages? Perhaps using mprotect or mmap with
        // PROT_NONE?

        let (hole_start, _hole_size) = self.holes.iter()
            .skip_while(|(hole_offset, hole_size)| hole_offset.data() + **hole_size <= min)
            .find(|(hole_offset, hole_size)| {
                let avail_size = if hole_offset.data() <= min && min <= hole_offset.data() + **hole_size {
                    **hole_size - (min - hole_offset.data())
                } else {
                    **hole_size
                };
                page_count * PAGE_SIZE <= avail_size
            })?;
        // Create new region
        Some(PageSpan::new(Page::containing_address(VirtualAddress::new(cmp::max(hole_start.data(), min))), page_count))
    }
    /// Return a free region, respecting the user's hinted address and flags. Address may be null.
    pub fn find_free_at(&mut self, min: usize, base: Option<Page>, page_count: usize, flags: MapFlags) -> Result<PageSpan> {
        let Some(requested_base) = base else {
            // Free hands!
            return self.find_free(min, page_count).ok_or(Error::new(ENOMEM));
        };

        // The user wished to have this region...
        let requested_span = PageSpan::new(requested_base, page_count);

        if let Some(_grant) = self.conflicts(requested_span).next() {
            // ... but it already exists

            if flags.contains(MapFlags::MAP_FIXED_NOREPLACE) {
                return Err(Error::new(EEXIST));
            }
            if flags.contains(MapFlags::MAP_FIXED) {
                return Err(Error::new(EOPNOTSUPP));
            } else {
                // TODO: Find grant close to requested address?
                return self.find_free(min, page_count).ok_or(Error::new(ENOMEM));
            }
        }

        Ok(requested_span)
    }
    fn reserve(&mut self, base: Page, page_count: usize) {
        let start_address = base.start_address();
        let size = page_count * PAGE_SIZE;
        let end_address = base.start_address().add(size);

        let previous_hole = self.holes.range_mut(..start_address).next_back();

        if let Some((hole_offset, hole_size)) = previous_hole {
            let prev_hole_end = hole_offset.data() + *hole_size;

            // Note that prev_hole_end cannot exactly equal start_address, since that would imply
            // there is another grant at that position already, as it would otherwise have been
            // larger.

            if prev_hole_end > start_address.data() {
                // hole_offset must be below (but never equal to) the start address due to the
                // `..start_address()` limit; hence, all we have to do is to shrink the
                // previous offset.
                *hole_size = start_address.data() - hole_offset.data();
            }
            if prev_hole_end > end_address.data() {
                // The grant is splitting this hole in two, so insert the new one at the end.
                self.holes.insert(end_address, prev_hole_end - end_address.data());
            }
        }

        // Next hole
        if let Some(hole_size) = self.holes.remove(&start_address) {
            let remainder = hole_size - size;
            if remainder > 0 {
                self.holes.insert(end_address, remainder);
            }
        }
    }
    fn unreserve(holes: &mut BTreeMap<VirtualAddress, usize>, base: Page, page_count: usize) {
        // TODO
        let start_address = base.start_address();
        let size = page_count * PAGE_SIZE;
        let end_address = base.start_address().add(size);

        // The size of any possible hole directly after the to-be-freed region.
        let exactly_after_size = holes.remove(&end_address);

        // There was a range that began exactly prior to the to-be-freed region, so simply
        // increment the size such that it occupies the grant too. If in addition there was a grant
        // directly after the grant, include it too in the size.
        if let Some((hole_offset, hole_size)) = holes.range_mut(..start_address).next_back().filter(|(offset, size)| offset.data() + **size == start_address.data()) {
            *hole_size = end_address.data() - hole_offset.data() + exactly_after_size.unwrap_or(0);
        } else {
            // There was no free region directly before the to-be-freed region, however will
            // now unconditionally insert a new free region where the grant was, and add that extra
            // size if there was something after it.
            holes.insert(start_address, size + exactly_after_size.unwrap_or(0));
        }
    }
    pub fn insert(&mut self, grant: Grant) {
        assert!(self.conflicts(PageSpan::new(grant.base, grant.info.page_count)).next().is_none());
        self.reserve(grant.base, grant.info.page_count);

        // FIXME: This currently causes issues, mostly caused by old code that unmaps only based on
        // offsets. For instance, the scheme code does not specify any length, and would thus unmap
        // memory outside of what it intended to.

        /*
        let before_region = self.inner
            .range(..grant.base).next_back()
            .filter(|(base, info)| base.next_by(info.page_count) == grant.base && info.can_be_merged_if_adjacent(&grant.info)).map(|(base, info)| (*base, info.page_count));

        let after_region = self.inner
            .range(grant.span().end()..).next()
            .filter(|(base, info)| **base == grant.base.next_by(grant.info.page_count) && info.can_be_merged_if_adjacent(&grant.info)).map(|(base, info)| (*base, info.page_count));

        if let Some((before_base, before_page_count)) = before_region {
            grant.base = before_base;
            grant.info.page_count += before_page_count;

            core::mem::forget(self.inner.remove(&before_base));
        }
        if let Some((after_base, after_page_count)) = after_region {
            grant.info.page_count += after_page_count;

            core::mem::forget(self.inner.remove(&after_base));
        }
        */

        self.inner.insert(grant.base, grant.info);
    }
    pub fn remove(&mut self, base: Page) -> Option<Grant> {
        let info = self.inner.remove(&base)?;
        Self::unreserve(&mut self.holes, base, info.page_count);
        Some(Grant { base, info })
    }
    pub fn iter(&self) -> impl Iterator<Item = (Page, &GrantInfo)> + '_ {
        self.inner.iter().map(|(base, info)| (*base, info))
    }
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
    pub fn into_iter(self) -> impl Iterator<Item = Grant> {
        self.inner.into_iter().map(|(base, info)| Grant { base, info })
    }
}

#[derive(Debug)]
pub struct GrantInfo {
    page_count: usize,
    flags: PageFlags<RmmA>,
    // TODO: Rename to unmapped?
    mapped: bool,
    pub(crate) owned: bool,
    //TODO: This is probably a very heavy way to keep track of fmap'd files, perhaps move to the context?
    pub desc_opt: Option<GrantFileRef>,
}
#[derive(Debug)]
pub struct Grant {
    pub(crate) base: Page,
    pub(crate) info: GrantInfo,
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
    // TODO: PageCount newtype, to avoid confusion between bytes and pages?

    pub fn physmap(phys: Frame, dst: Page, page_count: usize, flags: PageFlags<RmmA>, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>) -> Result<Grant> {
        for index in 0..page_count {
            let result = unsafe {
                mapper
                    .map_phys(dst.next_by(index).start_address(), phys.next_by(index).start_address(), flags)
                    .expect("TODO: handle OOM from paging structures in physmap")
            };
            flusher.consume(result);
        }

        Ok(Grant {
            base: dst,
            info: GrantInfo {
                page_count,
                flags,
                mapped: true,
                owned: false,
                desc_opt: None,
            },
        })
    }
    pub fn zeroed(dst: Page, page_count: usize, flags: PageFlags<RmmA>, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>) -> Result<Grant, Enomem> {
        Ok(Grant { base: dst, info: GrantInfo { page_count, flags, mapped: true, owned: true, desc_opt: None } })
    }
    pub fn borrow(src_base: Page, dst_base: Page, page_count: usize, flags: PageFlags<RmmA>, desc_opt: Option<GrantFileRef>, src_mapper: &mut PageMapper, dst_mapper: &mut PageMapper, dst_flusher: impl Flusher<RmmA>) -> Result<Grant, Enomem> {
        Self::copy_inner(src_base, dst_base, page_count, flags, desc_opt, src_mapper, dst_mapper, (), dst_flusher, false, false)
    }
    pub fn reborrow(src_base: Page, src_info: &GrantInfo, dst_base: Page, src_mapper: &mut PageMapper, dst_mapper: &mut PageMapper, dst_flusher: impl Flusher<RmmA>) -> Result<Grant> {
        Self::borrow(src_base, dst_base, src_info.page_count, src_info.flags, src_info.desc_opt.clone(), src_mapper, dst_mapper, dst_flusher).map_err(Into::into)
    }
    pub fn transfer(mut src_grant: Grant, dst_base: Page, src_mapper: &mut PageMapper, dst_mapper: &mut PageMapper, src_flusher: impl Flusher<RmmA>, dst_flusher: impl Flusher<RmmA>) -> Result<Grant> {
        assert!(core::mem::replace(&mut src_grant.info.mapped, false));
        let desc_opt = src_grant.info.desc_opt.take();

        Self::copy_inner(src_grant.base, dst_base, src_grant.info.page_count, src_grant.info.flags(), desc_opt, src_mapper, dst_mapper, src_flusher, dst_flusher, src_grant.info.owned, true).map_err(Into::into)
    }

    fn copy_inner(
        src_base: Page,
        dst_base: Page,
        page_count: usize,
        flags: PageFlags<RmmA>,
        desc_opt: Option<GrantFileRef>,
        src_mapper: &mut PageMapper,
        dst_mapper: &mut PageMapper,
        mut src_flusher: impl Flusher<RmmA>,
        mut dst_flusher: impl Flusher<RmmA>,
        owned: bool,
        unmap: bool,
    ) -> Result<Grant, Enomem> {
        let mut successful_count = 0;

        for index in 0..page_count {
            let src_page = src_base.next_by(index);
            let (address, _entry_flags) = if unmap {
                let (entry, entry_flags, flush) = unsafe { src_mapper.unmap_phys(src_page.start_address(), true).expect("grant references unmapped memory") };
                src_flusher.consume(flush);

                (entry, entry_flags)
            } else {
                src_mapper.translate(src_page.start_address()).unwrap_or_else(|| panic!("grant at {:p} references unmapped memory", src_page.start_address().data() as *const u8))
            };

            let flush = match unsafe { dst_mapper.map_phys(dst_base.next_by(index).start_address(), address, flags) } {
                Some(f) => f,
                // ENOMEM
                None => break,
            };

            dst_flusher.consume(flush);

            successful_count = index + 1;
        }

        if successful_count != page_count {
            // TODO: The grant will be lost in case of ENOMEM. Allow putting it back in source?
            for index in 0..successful_count {
                let (frame, _, flush) = match unsafe { dst_mapper.unmap_phys(dst_base.next_by(index).start_address(), true) } {
                    Some(f) => f,
                    None => unreachable!("grant unmapped by someone else in the meantime despite having a &mut PageMapper"),
                };
                dst_flusher.consume(flush);

                if owned {
                    crate::memory::deallocate_frames(Frame::containing_address(frame), 1);
                }
            }
            return Err(Enomem);
        }

        Ok(Grant {
            base: dst_base,
            info: GrantInfo {
                page_count,
                flags,
                mapped: true,
                owned,
                desc_opt,
            },
        })
    }

    pub fn remap(&mut self, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>, flags: PageFlags<RmmA>) {
        assert!(self.info.mapped);

        for page in self.span().pages() {
            // TODO: PageMapper is unsafe because it can be used to modify kernel memory. Add a
            // subset/wrapper that is safe but only for user mappings.
            unsafe {
                let result = mapper.remap(page.start_address(), flags).expect("grant contained unmap address");
                flusher.consume(result);
            }
        }

        self.info.flags = flags;
    }
    pub fn unmap(mut self, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>) -> UnmapResult {
        assert!(self.info.mapped);

        for page in self.span().pages() {
            let (entry, _, flush) = unsafe { mapper.unmap_phys(page.start_address(), true) }
                .unwrap_or_else(|| panic!("missing page at {:#0x} for grant {:?}", page.start_address().data(), self));

            if self.info.owned {
                // TODO: make sure this frame can be safely freed, physical use counter.
                //
                // Namely, we can either have MAP_PRIVATE or MAP_SHARED-style mappings. The former
                // maps the source memory read-only and then (not yet) implements CoW on top (as of
                // now the kernel does not yet support this distinction), while the latter simply
                // means the memory is shared. We can in addition to the desc_opt also include an
                // address space and region within, indicating borrowed memory. The source grant
                // will have a refcount, and if it is unmapped, it will be transferred to a
                // borrower. Only if this refcount becomes zero when decremented, will it be
                // possible to unmap.
                //
                // So currently, it is technically possible to get double frees if the scheme
                // "hosting" the memory of an fmap call, decides to funmap its memory before the
                // fmapper does.
                crate::memory::deallocate_frames(Frame::containing_address(entry), 1);
            }
            flusher.consume(flush);
        }

        self.info.mapped = false;

        // TODO: This imposes a large cost on unmapping, but that cost cannot be avoided without modifying fmap and funmap
        UnmapResult { file_desc: self.info.desc_opt.take() }
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
    pub fn span(&self) -> PageSpan {
        PageSpan::new(self.base, self.info.page_count)
    }
    pub fn extract(mut self, span: PageSpan) -> Option<(Option<Grant>, Grant, Option<Grant>)> {
        let (before_span, this_span, after_span) = self.span().slice(span);

        let before_grant = before_span.map(|span| Grant {
            base: span.base,
            info: GrantInfo {
                flags: self.info.flags,
                mapped: self.info.mapped,
                owned: self.info.owned,
                desc_opt: self.info.desc_opt.clone(),
                page_count: span.count,
            },
        });
        let after_grant = after_span.map(|span| Grant {
            base: span.base,
            info: GrantInfo {
                flags: self.info.flags,
                mapped: self.info.mapped,
                owned: self.info.owned,
                desc_opt: self.info.desc_opt.clone(),
                page_count: span.count,
            },
        });
        self.base = this_span.base;
        self.info.page_count = this_span.count;

        Some((before_grant, self, after_grant))
    }
}
impl GrantInfo {
    pub fn flags(&self) -> PageFlags<RmmA> {
        self.flags
    }
    pub fn is_owned(&self) -> bool {
        self.owned
    }
    pub fn page_count(&self) -> usize {
        self.page_count
    }
    pub fn can_have_flags(&self, flags: MapFlags) -> bool {
        self.owned || ((self.flags.has_write() || !flags.contains(MapFlags::PROT_WRITE)) && (self.flags.has_execute() || !flags.contains(MapFlags::PROT_EXEC)))
    }

    pub fn can_be_merged_if_adjacent(&self, with: &Self) -> bool {
        match (&self.desc_opt, &with.desc_opt) {
            (None, None) => (),
            (Some(ref a), Some(ref b)) if Arc::ptr_eq(&a.desc.description, &b.desc.description) => (),

            _ => return false,
        }
        self.owned == with.owned && self.mapped == with.mapped && self.flags.data() == with.flags.data()
    }
}

impl Drop for GrantInfo {
    fn drop(&mut self) {
        // XXX: This will not show the address...
        assert!(!self.mapped, "Grant dropped while still mapped: {:#x?}", self);
    }
}

pub const DANGLING: usize = 1 << (usize::BITS - 2);

#[derive(Debug)]
pub struct Table {
    pub utable: PageMapper,
}

impl Drop for Table {
    fn drop(&mut self) {
        if self.utable.is_current() {
            // TODO: Do not flush (we immediately context switch after exit(), what else is there
            // to do?). Instead, we can garbage-collect such page tables in the idle kernel context
            // before it waits for interrupts. Or maybe not, depends on what future benchmarks will
            // indicate.
            unsafe {
                RmmA::set_table(TableKind::User, super::empty_cr3());
            }
        }
        crate::memory::deallocate_frames(Frame::containing_address(self.utable.table().phys()), 1);
    }
}

/// Allocates a new empty utable
#[cfg(target_arch = "aarch64")]
pub fn setup_new_utable() -> Result<Table> {
    let utable = unsafe { PageMapper::create(TableKind::User, crate::rmm::FRAME_ALLOCATOR).ok_or(Error::new(ENOMEM))? };

    Ok(Table {
        utable,
    })
}

/// Allocates a new identically mapped ktable and empty utable (same memory on x86)
#[cfg(target_arch = "x86")]
pub fn setup_new_utable() -> Result<Table> {
    let mut utable = unsafe { PageMapper::create(TableKind::User, crate::rmm::FRAME_ALLOCATOR).ok_or(Error::new(ENOMEM))? };

    {
        let active_ktable = KernelMapper::lock();

        let mut copy_mapping = |p4_no| unsafe {
            let entry = active_ktable.table().entry(p4_no)
                .unwrap_or_else(|| panic!("expected kernel PML {} to be mapped", p4_no));

            utable.table().set_entry(p4_no, entry)
        };

        // Copy higher half (kernel) mappings
        for i in 512..1024 {
            copy_mapping(i);
        }
    }

    Ok(Table {
        utable,
    })
}

/// Allocates a new identically mapped ktable and empty utable (same memory on x86_64).
#[cfg(target_arch = "x86_64")]
pub fn setup_new_utable() -> Result<Table> {
    let utable = unsafe { PageMapper::create(TableKind::User, crate::rmm::FRAME_ALLOCATOR).ok_or(Error::new(ENOMEM))? };

    {
        let active_ktable = KernelMapper::lock();

        let copy_mapping = |p4_no| unsafe {
            let entry = active_ktable.table().entry(p4_no)
                .unwrap_or_else(|| panic!("expected kernel PML {} to be mapped", p4_no));

            utable.table().set_entry(p4_no, entry)
        };
        // TODO: Just copy all 256 mappings? Or copy KERNEL_PML4+KERNEL_PERCPU_PML4 (needed for
        // paranoid ISRs which can occur anywhere; we don't want interrupts to triple fault!) and
        // map lazily via page faults in the kernel.

        // Copy kernel image mapping
        copy_mapping(crate::KERNEL_PML4);

        // Copy kernel heap mapping
        copy_mapping(crate::KERNEL_HEAP_PML4);

        // Copy physmap mapping
        copy_mapping(crate::PHYS_PML4);
    }

    Ok(Table {
        utable,
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
