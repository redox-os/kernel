use alloc::collections::BTreeMap;
use alloc::{sync::Arc, vec::Vec};
use syscall::{GrantFlags, MunmapFlags};
use core::cmp;
use core::fmt::Debug;
use core::num::NonZeroUsize;
use core::sync::atomic::Ordering;
use spin::{RwLock, RwLockWriteGuard, RwLockUpgradableGuard};
use syscall::{
    flag::MapFlags,
    error::*,
};
use rmm::{Arch as _, PageFlush};

use crate::arch::paging::PAGE_SIZE;
use crate::memory::{Enomem, Frame, get_page_info, PageInfo, deallocate_frames, RefKind, AddRefError, RefCount, the_zeroed_frame};
use crate::paging::mapper::{Flusher, InactiveFlusher, PageFlushAll};
use crate::paging::{Page, PageFlags, PageMapper, RmmA, TableKind, VirtualAddress};
use crate::scheme;

use super::context::HardBlockedReason;
use super::file::FileDescription;

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
    flags
}

pub struct UnmapResult {
    pub file_desc: Option<GrantFileRef>,
    pub size: usize,
    pub flags: MunmapFlags,
}
impl UnmapResult {
    pub fn unmap(mut self) -> Result<()> {
        let Some(GrantFileRef { base_offset, description }) = self.file_desc.take() else {
            return Ok(());
        };

        let (scheme_id, number) = match description.write() {
            ref desc => (desc.scheme, desc.number),
        };

        let funmap_result = crate::scheme::schemes()
            .get(scheme_id).map(Arc::clone).ok_or(Error::new(ENODEV))
            .and_then(|scheme| scheme.kfunmap(number, base_offset, self.size, self.flags));

        if let Ok(fd) = Arc::try_unwrap(description) {
            fd.into_inner().try_close()?;
        }
        funmap_result?;

        Ok(())
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
        let mut this_flusher = PageFlushAll::new();

        for (grant_base, grant_info) in self.grants.iter() {
            let new_grant = match grant_info.provider {
                // No, your temporary UserScheme mappings will not be kept across forks.
                Provider::External { is_pinned_userscheme_borrow: true, .. } | Provider::AllocatedShared { is_pinned_userscheme_borrow: true, .. } => continue,

                Provider::PhysBorrowed { base } => Grant::physmap(
                    base.clone(),
                    PageSpan::new(grant_base, grant_info.page_count),
                    grant_info.flags,
                    new_mapper,
                    (),
                )?,
                Provider::Allocated { ref cow_file_ref } => Grant::copy_mappings(
                    grant_base,
                    grant_base,
                    grant_info.page_count,
                    grant_info.flags,
                    this_mapper,
                    new_mapper,
                    &mut this_flusher,
                    (),
                    CopyMappingsMode::Owned { cow_file_ref: cow_file_ref.clone() },
                )?,
                // TODO: Merge Allocated and AllocatedShared, and make CopyMappingsMode a field?
                Provider::AllocatedShared { is_pinned_userscheme_borrow: false } => Grant::copy_mappings(
                    grant_base,
                    grant_base,
                    grant_info.page_count,
                    grant_info.flags,
                    this_mapper,
                    new_mapper,
                    &mut this_flusher,
                    (),
                    CopyMappingsMode::Borrowed,
                )?,

                // MAP_SHARED grants are retained by reference, across address space clones (across
                // forks on monolithic kernels).
                Provider::External { ref address_space, src_base, .. } => Grant::borrow_grant(
                    Arc::clone(&address_space),
                    src_base,
                    grant_base,
                    grant_info,
                    new_mapper,
                    (),
                    false,
                )?,
                Provider::FmapBorrowed { .. } => continue,
            };

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
        let regions = self.grants.conflicts(requested_span).map(|(base, info)| if info.is_pinned() {
            Err(Error::new(EBUSY))
        } else {
            Ok(PageSpan::new(base, info.page_count))
        }).collect::<Vec<_>>();

        for grant_span_res in regions {
            let grant_span = grant_span_res?;

            let grant = self.grants.remove(grant_span.base).expect("grant cannot magically disappear while we hold the lock!");
            //log::info!("Mprotecting {:#?} to {:#?} in {:#?}", grant, flags, grant_span);
            let intersection = grant_span.intersection(requested_span);

            let (before, mut grant, after) = grant.extract(intersection).expect("failed to extract grant");
            //log::info!("Sliced into\n\n{:#?}\n\n{:#?}\n\n{:#?}", before, grant, after);

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
            //log::info!("Mprotect grant became {:#?}", grant);
            self.grants.insert(grant);
        }
        Ok(())
    }
    #[must_use = "needs to notify files"]
    pub fn munmap(&mut self, mut requested_span: PageSpan, unpin: bool) -> Result<Vec<UnmapResult>> {
        let mut notify_files = Vec::new();

        let mut flusher = PageFlushAll::new();

        let this = &mut *self;

        let next = |grants: &mut UserGrants, span: PageSpan| grants.conflicts(span).map(|(base, info)| if info.is_pinned() && !unpin {
            Err(Error::new(EBUSY))
        } else {
            Ok(PageSpan::new(base, info.page_count))
        }).next();

        while let Some(conflicting_span_res) = next(&mut this.grants, requested_span) {
            let conflicting_span = conflicting_span_res?;

            let mut grant = this.grants.remove(conflicting_span.base).expect("conflicting region didn't exist");
            if unpin {
                grant.info.unpin();
            }

            let intersection = conflicting_span.intersection(requested_span);

            requested_span = {
                let offset = conflicting_span.base.offset_from(requested_span.base);
                PageSpan::new(conflicting_span.end(), requested_span.count - offset - conflicting_span.count)
            };

            let (before, grant, after) = grant.extract(intersection).expect("conflicting region shared no common parts");

            // Keep untouched regions
            if let Some(before) = before {
                this.grants.insert(before);
            }
            if let Some(after) = after {
                this.grants.insert(after);
            }

            // Remove irrelevant region
            let unmap_result = grant.unmap(&mut this.table.utable, &mut flusher);

            // Notify scheme that holds grant
            if unmap_result.file_desc.is_some() {
                notify_files.push(unmap_result);
            }
        }

        Ok(notify_files)
    }
    pub fn mmap_anywhere(&mut self, page_count: NonZeroUsize, flags: MapFlags, map: impl FnOnce(Page, PageFlags<RmmA>, &mut PageMapper, &mut dyn Flusher<RmmA>) -> Result<Grant>) -> Result<Page> {
        self.mmap(None, page_count, flags, &mut Vec::new(), map)
    }
    pub fn mmap(
        &mut self,
        requested_base_opt: Option<Page>,
        page_count: NonZeroUsize,
        flags: MapFlags,
        notify_files_out: &mut Vec<UnmapResult>,
        map: impl FnOnce(Page, PageFlags<RmmA>, &mut PageMapper, &mut dyn Flusher<RmmA>) -> Result<Grant>,
    ) -> Result<Page> {
        let selected_span = match requested_base_opt {
            Some(requested_base) => {
                let requested_span = PageSpan::new(requested_base, page_count.get());

                if flags.contains(MapFlags::MAP_FIXED_NOREPLACE) && self.grants.conflicts(requested_span).next().is_some() {
                    return Err(Error::new(EEXIST));
                }

                // TODO: Rename MAP_FIXED+MAP_FIXED_NOREPLACE to MAP_FIXED and
                // MAP_FIXED_REPLACE/MAP_REPLACE?
                let map_fixed_replace = flags.contains(MapFlags::MAP_FIXED);

                if map_fixed_replace {
                    let unpin = false;
                    let mut notify_files = self.munmap(requested_span, unpin)?;
                    notify_files_out.append(&mut notify_files);

                    requested_span
                } else {
                    self.grants.find_free_near(self.mmap_min, page_count.get(), Some(requested_base)).ok_or(Error::new(ENOMEM))?
                }
            }
            None => self.grants.find_free(self.mmap_min, page_count.get()).ok_or(Error::new(ENOMEM))?,
        };

        // TODO: Threads share address spaces, so not only the inactive flusher should be sending
        // out IPIs. IPIs will only be sent when downgrading mappings (i.e. when a stale TLB entry
        // will not be corrected by a page fault), and will furthermore require proper
        // synchronization.
        let (mut active, mut inactive);
        let flusher = if self.is_current() {
            active = PageFlushAll::new();
            &mut active as &mut dyn Flusher<RmmA>
        } else {
            inactive = InactiveFlusher::new();
            &mut inactive as &mut dyn Flusher<RmmA>
        };

        let grant = map(selected_span.base, page_flags(flags), &mut self.table.utable, flusher)?;
        self.grants.insert(grant);

        Ok(selected_span.base)
    }
    pub fn r#move(dst: &mut AddrSpace, mut src_opt: Option<&mut AddrSpace>, src_span: PageSpan, requested_dst_base: Option<Page>, new_flags: MapFlags, notify_files: &mut Vec<UnmapResult>) -> Result<Page> {
        let nz_count = NonZeroUsize::new(src_span.count).ok_or(Error::new(EINVAL))?;

        let src = src_opt.as_deref_mut().unwrap_or(&mut *dst);

        let grant_base = {
            let mut conflicts_iter = src.grants.conflicts(src_span);

            let (grant_base, grant_info) = conflicts_iter.next().ok_or(Error::new(EINVAL))?;

            if conflicts_iter.next().is_some() {
                return Err(Error::new(EINVAL));
            }
            if grant_info.is_pinned() {
                return Err(Error::new(EBUSY));
            }

            grant_base
        };

        let grant = src.grants.remove(grant_base).expect("grant cannot disappear");
        let (before, middle, after) = grant.extract(src_span).expect("called intersect(), must succeed");

        if let Some(before) = before { src.grants.insert(before); }
        if let Some(after) = after { src.grants.insert(after); }

        let src_flusher = PageFlushAll::new();

        if let Some(src) = src_opt {
            dst.mmap(requested_dst_base, nz_count, new_flags, notify_files, |dst_page, flags, dst_mapper, dst_flusher| middle.transfer(dst_page, flags, &mut src.table.utable, Some(dst_mapper), src_flusher, dst_flusher))
        } else {
            dst.mmap(requested_dst_base, nz_count, new_flags, notify_files, |dst_page, flags, dst_mapper, dst_flusher| middle.transfer(dst_page, flags, dst_mapper, None, src_flusher, dst_flusher))
        }
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
    // TODO: Deduplicate code?
    pub fn contains_mut(&mut self, page: Page) -> Option<(Page, &mut GrantInfo)> {
        self.inner
            .range_mut(..=page)
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
    // TODO: DEDUPLICATE CODE!
    pub fn conflicts_mut(&mut self, span: PageSpan) -> impl Iterator<Item = (Page, &'_ mut GrantInfo)> + '_ {
        let start = self.contains(span.base);

        // If there is a grant that contains the base page, start searching at the base of that
        // grant, rather than the requested base here.
        let start_span = start.map(|(base, info)| PageSpan::new(base, info.page_count)).unwrap_or(span);

        self
            .inner
            .range_mut(start_span.base..)
            .take_while(move |(base, info)| PageSpan::new(**base, info.page_count).intersects(span))
            .map(|(base, info)| (*base, info))
    }
    /// Return a free region with the specified size
    // TODO: Alignment (x86_64: 4 KiB, 2 MiB, or 1 GiB).
    // TODO: Support finding grant close to a requested address?
    pub fn find_free_near(&self, min: usize, page_count: usize, _near: Option<Page>) -> Option<PageSpan> {
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
    pub fn find_free(&self, min: usize, page_count: usize) -> Option<PageSpan> {
        self.find_free_near(min, page_count, None)
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
    pub(crate) provider: Provider,
}

/// Enumeration of various types of grants.
#[derive(Debug)]
pub enum Provider {
    /// The grant is owned, but possibly CoW-shared.
    ///
    /// The pages this grant spans, need not necessarily be initialized right away, and can be
    /// populated either from zeroed frames, the CoW zeroed frame, or from a scheme fmap call, if
    /// mapped with MAP_LAZY. All frames must have an available PageInfo.
    Allocated { cow_file_ref: Option<GrantFileRef> },

    /// The grant is owned, but possibly shared.
    ///
    /// The pages may only be lazily initialized, if the address space has not yet been cloned (when forking).
    ///
    /// This type of grants is obtained from MAP_SHARED anonymous or `memory:` mappings, i.e.
    /// allocated memory that remains shared after address space clones.
    AllocatedShared { is_pinned_userscheme_borrow: bool },

    /// The grant is not owned, but borrowed from physical memory frames that do not belong to the
    /// frame allocator.
    ///
    /// This is true for MMIO, or where the frames are managed externally (UserScheme head/tail
    /// buffers).
    ///
    // TODO: Stop using PhysBorrowed for head/tail pages when doing scheme calls! Force userspace
    // to provide it, perhaps from relibc?
    PhysBorrowed { base: Frame },

    /// The memory is borrowed directly from another address space.
    External { address_space: Arc<RwLock<AddrSpace>>, src_base: Page, is_pinned_userscheme_borrow: bool },

    /// The memory is MAP_SHARED borrowed from a scheme.
    ///
    /// Since the address space is not tracked here, all nonpresent pages must be present before
    /// the fmap operation completes, unless MAP_LAZY is specified. They are tracked using
    /// PageInfo, or treated as PhysBorrowed if any frame lacks a PageInfo.
    FmapBorrowed { file_ref: GrantFileRef, pin_refcount: usize },
}

#[derive(Debug)]
pub struct Grant {
    pub(crate) base: Page,
    pub(crate) info: GrantInfo,
}

#[derive(Clone, Debug)]
pub struct GrantFileRef {
    pub description: Arc<RwLock<FileDescription>>,
    pub base_offset: usize,
}

impl Grant {
    // TODO: PageCount newtype, to avoid confusion between bytes and pages?

    // TODO: is_pinned
    pub fn allocated_shared_one_page(frame: Frame, page: Page, flags: PageFlags<RmmA>, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>, is_pinned: bool) -> Result<Grant> {
        let info = get_page_info(frame).expect("needs page info");

        // TODO:
        //
        // This may not necessarily hold, as even pinned memory can remain shared (e.g.
        // proc: borrow), but it would probably be possible to forbid borrowing memory
        // there as well.
        //
        // assert_eq!(info.refcount(), RefCount::One);

        // Semantically, the page will be shared between the "context struct" and whatever
        // else.
        info.add_ref(RefKind::Shared).expect("must be possible if previously Zero");

        unsafe {
            flusher.consume(mapper.map_phys(page.start_address(), frame.start_address(), flags).ok_or(Error::new(ENOMEM))?);
        }

        Ok(Grant {
            base: page,
            info: GrantInfo {
                page_count: 1,
                flags,
                mapped: true,
                provider: Provider::AllocatedShared { is_pinned_userscheme_borrow: is_pinned },
            }
        })
    }

    pub fn physmap(phys: Frame, span: PageSpan, flags: PageFlags<RmmA>, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>) -> Result<Grant> {
        const MAX_EAGER_PAGES: usize = 4096;

        for (i, page) in span.pages().enumerate().take(MAX_EAGER_PAGES) {
            unsafe {
                let Some(result) = mapper.map_phys(page.start_address(), phys.next_by(i).start_address(), flags.write(false)) else {
                    break;
                };
                flusher.consume(result);
            }
        }

        Ok(Grant {
            base: span.base,
            info: GrantInfo {
                page_count: span.count,
                flags,
                mapped: true,
                provider: Provider::PhysBorrowed { base: phys },
            },
        })
    }
    pub fn zeroed(span: PageSpan, flags: PageFlags<RmmA>, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>, shared: bool) -> Result<Grant, Enomem> {
        const MAX_EAGER_PAGES: usize = 16;

        let (the_frame, the_frame_info) = the_zeroed_frame();

        // TODO: Use flush_all after a certain number of pages, otherwise no

        for page in span.pages().take(MAX_EAGER_PAGES) {
            // Good thing with lazy page fault handlers, is that if we fail due to ENOMEM here, we
            // can continue and let the process face the OOM killer later.
            unsafe {
                the_frame_info.add_ref(RefKind::Cow).expect("the static zeroed frame cannot be shared!");

                let Some(result) = mapper.map_phys(page.start_address(), the_frame.start_address(), flags.write(false)) else {
                    break;
                };
                flusher.consume(result);
            }
        }

        Ok(Grant {
            base: span.base,
            info: GrantInfo {
                page_count: span.count,
                flags,
                mapped: true,
                provider: if shared {
                    Provider::AllocatedShared { is_pinned_userscheme_borrow: false }
                } else {
                    Provider::Allocated { cow_file_ref: None }
                },
            },
        })
    }

    // XXX: borrow_grant is needed because of the borrow checker (iterator invalidation), maybe
    // borrow_grant/borrow can be abstracted somehow?
    pub fn borrow_grant(src_address_space_lock: Arc<RwLock<AddrSpace>>, src_base: Page, dst_base: Page, src_info: &GrantInfo, _mapper: &mut PageMapper, _dst_flusher: impl Flusher<RmmA>, _eager: bool) -> Result<Grant, Enomem> {
        Ok(Grant {
            base: dst_base,
            info: GrantInfo {
                page_count: src_info.page_count,
                flags: src_info.flags,
                mapped: true,
                provider: Provider::External {
                    src_base,
                    address_space: src_address_space_lock,
                    is_pinned_userscheme_borrow: false,
                }
            },
        })
    }

    pub fn borrow_fmap(span: PageSpan, new_flags: PageFlags<RmmA>, file_ref: GrantFileRef, src: Option<BorrowedFmapSource<'_>>, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>) -> Result<Self> {
        if let Some(src) = src {
            let mut guard = src.addr_space_guard;
            for dst_page in span.pages() {
                let src_page = src.src_base.next_by(dst_page.offset_from(span.base));

                let (frame, is_cow) = match src.mode {
                    MmapMode::Shared => {
                        // TODO: Error code for "scheme responded with unmapped page"?
                        let frame = match guard.table.utable.translate(src_page.start_address()) {
                            Some((phys, _)) => Frame::containing_address(phys),
                            // TODO: ensure the correct context is hardblocked, if necessary
                            None => {
                                let (frame, _, new_guard) = correct_inner(src.addr_space_lock, guard, src_page, AccessMode::Read, 0).map_err(|_| Error::new(EIO))?;
                                guard = new_guard;
                                frame
                            }
                        };

                        (frame, false)
                    }
                    /*
                    MmapMode::Cow => unsafe {
                        let frame = match guard.table.utable.remap_with(src_page.start_address(), |flags| flags.write(false)) {
                            Some((_, phys, _)) => Frame::containing_address(phys),
                            // TODO: ensure the correct context is hardblocked, if necessary
                            None => {
                                let (frame, _, new_guard) = correct_inner(src.addr_space_lock, guard, src_page, AccessMode::Read, 0).map_err(|_| Error::new(EIO))?;
                                guard = new_guard;
                                frame
                            }
                        };

                        (frame, true)
                    }
                    */
                    MmapMode::Cow => return Err(Error::new(EOPNOTSUPP)),
                };

                let frame = if let Some(page_info) = get_page_info(frame) {
                    match page_info.add_ref(RefKind::Shared) {
                        Ok(()) => frame,
                        Err(AddRefError::CowToShared) => cow(frame, page_info, RefKind::Shared).map_err(|_| Error::new(ENOMEM))?,
                        Err(AddRefError::SharedToCow) => unreachable!(),
                        Err(AddRefError::RcOverflow) => return Err(Error::new(ENOMEM)),
                    }
                } else { frame };

                unsafe {
                    flusher.consume(mapper.map_phys(dst_page.start_address(), frame.start_address(), new_flags.write(new_flags.has_write() && !is_cow)).unwrap());
                }
            }
        }

        Ok(Self {
            base: span.base,
            info: GrantInfo {
                page_count: span.count,
                mapped: true,
                flags: new_flags,
                provider: Provider::FmapBorrowed { file_ref, pin_refcount: 0 },
            }
        })
    }

    /// Borrow all pages in the range `[src_base, src_base+page_count)` from `src_address_space`,
    /// mapping them into `[dst_base, dst_base+page_count)`. The destination pages will lazily read
    /// the page tables of the source pages, but once present in the destination address space,
    /// pages that are unmaped or moved will not be made visible to the destination address space.
    pub fn borrow(
        src_address_space_lock: Arc<RwLock<AddrSpace>>,
        src_address_space: &mut AddrSpace,
        src_base: Page,
        dst_base: Page,
        page_count: usize,
        flags: PageFlags<RmmA>,
        dst_mapper: &mut PageMapper,
        mut dst_flusher: impl Flusher<RmmA>,
        eager: bool,
        _allow_phys: bool,
        is_pinned_userscheme_borrow: bool,
    ) -> Result<Grant> {
        const MAX_EAGER_PAGES: usize = 4096;

        if eager {
            for (i, page) in PageSpan::new(src_base, page_count).pages().enumerate().take(MAX_EAGER_PAGES) {
                let Some((phys, _)) = src_address_space.table.utable.translate(page.start_address()) else {
                    continue;
                };

                let writable = match get_page_info(Frame::containing_address(phys)) {
                    // TODO: this is a hack for PhysBorrowed pages
                    None => false,
                    Some(i) => {
                        if i.add_ref(RefKind::Shared).is_err() {
                            continue;
                        };

                        i.allows_writable()
                    }
                };

                unsafe {
                    let flush = dst_mapper.map_phys(dst_base.next_by(i).start_address(), phys, flags.write(writable)).ok_or(Error::new(ENOMEM))?;
                    dst_flusher.consume(flush);
                }
            }
        }

        let src_span = PageSpan::new(src_base, page_count);
        let mut prev_span = None;

        for (src_grant_base, src_grant) in src_address_space.grants.conflicts_mut(src_span) {
            if let Provider::FmapBorrowed { ref mut pin_refcount, .. } = src_grant.provider {
                *pin_refcount += 1;
            }

            let grant_span = PageSpan::new(src_grant_base, src_grant.page_count);
            let prev_span = prev_span.replace(grant_span);

            if prev_span.is_none() && src_grant_base > src_base {
                log::warn!("Grant too far away, prev_span {:?} src_base {:?} grant base {:?} grant {:#?}", prev_span, src_base, src_grant_base, src_grant);
                return Err(Error::new(EINVAL));
            } else if let Some(prev) = prev_span && prev.end() != src_grant_base {
                log::warn!("Hole between grants, prev_span {:?} src_base {:?} grant base {:?} grant {:#?}", prev_span, src_base, src_grant_base, src_grant);
                return Err(Error::new(EINVAL));
            }
        }

        let Some(last_span) = prev_span else {
            log::warn!("Called Grant::borrow, but no grants were there!");
            return Err(Error::new(EINVAL));
        };

        if last_span.end() < src_span.end() {
            log::warn!("Requested end page too far away from last grant");
            return Err(Error::new(EINVAL));
        }

        Ok(Grant {
            base: dst_base,
            info: GrantInfo {
                page_count,
                flags,
                mapped: true,
                provider: Provider::External { address_space: src_address_space_lock, src_base, is_pinned_userscheme_borrow }
            },
        })
    }
    // TODO: This is limited to one grant. Should it be (if some magic new proc: API is introduced)?
    pub fn copy_mappings(
        src_base: Page,
        dst_base: Page,
        page_count: usize,
        flags: PageFlags<RmmA>,
        src_mapper: &mut PageMapper,
        dst_mapper: &mut PageMapper,
        mut src_flusher: impl Flusher<RmmA>,
        mut dst_flusher: impl Flusher<RmmA>,
        mode: CopyMappingsMode,
    ) -> Result<Grant, Enomem> {
        let (allows_writable, rk) = match mode {
            CopyMappingsMode::Owned { .. } => (false, RefKind::Cow),
            CopyMappingsMode::Borrowed => (true, RefKind::Shared),
        };

        // TODO: Page table iterator
        for page_idx in 0..page_count {
            let src_page = src_base.next_by(page_idx);
            let dst_page = dst_base.next_by(page_idx).start_address();

            let src_frame = match rk {
                RefKind::Cow => {
                    let Some((_, phys, flush)) = (unsafe { src_mapper.remap_with(src_page.start_address(), |flags| flags.write(false)) }) else {
                        // Page is not mapped, let the page fault handler take care of that (initializing
                        // it to zero).
                        //
                        // TODO: If eager, allocate zeroed page if writable, or use *the* zeroed page (also
                        // for read-only)?
                        continue;
                    };
                    src_flusher.consume(flush);

                    Frame::containing_address(phys)
                }
                RefKind::Shared => {
                    if let Some((phys, _)) = src_mapper.translate(src_page.start_address()) {
                        Frame::containing_address(phys)
                    } else {
                        let new_frame = init_frame(RefCount::Shared(NonZeroUsize::new(2).unwrap())).expect("TODO: handle OOM");
                        let src_flush = unsafe { src_mapper.map_phys(src_page.start_address(), new_frame.start_address(), flags).expect("TODO: handle OOM") };
                        src_flusher.consume(src_flush);

                        new_frame
                    }
                }
            };

            let src_frame = {
                let src_page_info = get_page_info(src_frame).expect("allocated page was not present in the global page array");

                match src_page_info.add_ref(rk) {
                    Ok(()) => src_frame,
                    Err(AddRefError::RcOverflow) => return Err(Enomem),
                    Err(AddRefError::CowToShared) => {
                        let new_frame = cow(src_frame, src_page_info, rk).map_err(|_| Enomem)?;

                        // TODO: Flusher
                        unsafe {
                            src_mapper.remap_with_full(src_page.start_address(), |_, f| (new_frame.start_address(), f));
                        }

                        new_frame
                    },
                    // Cannot be shared and CoW simultaneously.
                    Err(AddRefError::SharedToCow) => {
                        // TODO: Copy in place, or use a zeroed page?
                        cow(src_frame, src_page_info, rk).map_err(|_| Enomem)?
                    },
                }
            };

            let Some(map_result) = (unsafe { dst_mapper.map_phys(dst_page, src_frame.start_address(), flags.write(flags.has_write() && allows_writable)) }) else {
                break;
            };

            dst_flusher.consume(map_result);
        }

        Ok(Grant {
            base: dst_base,
            info: GrantInfo {
                page_count,
                flags,
                mapped: true,
                provider: match mode {
                    CopyMappingsMode::Owned { cow_file_ref } => Provider::Allocated { cow_file_ref },
                    CopyMappingsMode::Borrowed => Provider::AllocatedShared { is_pinned_userscheme_borrow: false },
                },
            }
        })
    }
    /// Move a grant between two address spaces.
    pub fn transfer(self, dst_base: Page, flags: PageFlags<RmmA>, src_mapper: &mut PageMapper, mut dst_mapper: Option<&mut PageMapper>, mut src_flusher: impl Flusher<RmmA>, mut dst_flusher: impl Flusher<RmmA>) -> Result<Grant> {
        assert!(!self.info.is_pinned());

        for src_page in self.span().pages() {
            let dst_page = dst_base.next_by(src_page.offset_from(self.base));

            let unmap_parents = true;

            // TODO: Validate flags?
            let Some((phys, _flags, flush)) = (unsafe { src_mapper.unmap_phys(src_page.start_address(), unmap_parents) }) else {
                continue;
            };
            src_flusher.consume(flush);

            let dst_mapper = dst_mapper.as_deref_mut().unwrap_or(&mut *src_mapper);

            // TODO: Preallocate to handle OOM?
            let flush = unsafe { dst_mapper.map_phys(dst_page.start_address(), phys, flags).expect("TODO: OOM") };
            dst_flusher.consume(flush);
        }

        Ok(self)
    }

    pub fn remap(&mut self, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>, flags: PageFlags<RmmA>) {
        assert!(self.info.mapped);

        for page in self.span().pages() {
            unsafe {
                // Lazy mappings don't require remapping, as info.flags will be updated.
                let Some(result) = mapper.remap(page.start_address(), flags) else {
                    continue;
                };
                //log::info!("Remapped page {:?} (frame {:?})", page, Frame::containing_address(mapper.translate(page.start_address()).unwrap().0));
                flusher.consume(result);
            }
        }

        self.info.flags = flags;
    }
    #[must_use = "will not unmap itself"]
    pub fn unmap(mut self, mapper: &mut PageMapper, mut flusher: impl Flusher<RmmA>) -> UnmapResult {
        assert!(self.info.mapped);
        assert!(!self.info.is_pinned());

        if let Provider::External { ref address_space, src_base, .. } = self.info.provider {
            let mut guard = address_space.write();

            for (_, grant) in guard.grants.conflicts_mut(PageSpan::new(src_base, self.info.page_count)) {
                match grant.provider {
                    Provider::FmapBorrowed { ref mut pin_refcount, .. } => *pin_refcount = pin_refcount.checked_sub(1).expect("fmap pinning code is wrong"),
                    _ => continue,
                }
            }

            // TODO: Verify deadlock immunity
        }
        let (use_info, require_info, is_fmap_shared) = match self.info.provider {
            Provider::Allocated { .. } => (true, true, Some(false)),
            Provider::AllocatedShared { .. } => (true, true, None),
            Provider::External { .. } => (true, false, None),
            Provider::PhysBorrowed { .. } => (false, false, None),
            Provider::FmapBorrowed { .. } => (true, false, Some(true)),
        };

        for page in self.span().pages() {
            // Lazy mappings do not need to be unmapped.
            let Some((phys, _, flush)) = (unsafe { mapper.unmap_phys(page.start_address(), true) }) else {
                continue;
            };
            let frame = Frame::containing_address(phys);

            // TODO: use_info IS A HACK! It shouldn't be possible to obtain *any* PhysBorrowed
            // grants to allocator-owned memory! Replace physalloc/physfree with something like
            // madvise(range, PHYSICALLY_CONTIGUOUS).

            if use_info && let Some(info) = get_page_info(frame) {
                if info.remove_ref() == RefCount::Zero {
                    deallocate_frames(frame, 1);
                };
            } else {
                assert!(!require_info, "allocated frame did not have an associated PageInfo");
            }


            flusher.consume(flush);
        }

        self.info.mapped = false;

        // Dummy value, won't be read.
        let provider = core::mem::replace(&mut self.info.provider, Provider::AllocatedShared { is_pinned_userscheme_borrow: false });

        let mut munmap_flags = MunmapFlags::empty();
        munmap_flags.set(MunmapFlags::NEEDS_SYNC, is_fmap_shared.unwrap_or(false) && self.info.flags.has_write());

        UnmapResult {
            size: self.info.page_count * PAGE_SIZE,
            file_desc: match provider {
                Provider::Allocated { cow_file_ref } => cow_file_ref,
                Provider::FmapBorrowed { file_ref, .. } => Some(file_ref),
                _ => None,
            },
            flags: munmap_flags,
        }
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
        assert!(!self.info.is_pinned(), "forgot to enforce that UserScheme mappings cannot be split");

        let (before_span, this_span, after_span) = self.span().slice(span);

        let before_grant = before_span.map(|span| Grant {
            base: span.base,
            info: GrantInfo {
                flags: self.info.flags,
                mapped: self.info.mapped,
                page_count: span.count,
                provider: match self.info.provider {
                    Provider::External { ref address_space, src_base, .. } => Provider::External {
                        address_space: Arc::clone(address_space),
                        src_base,
                        is_pinned_userscheme_borrow: false,
                    },
                    Provider::Allocated { ref cow_file_ref } => Provider::Allocated { cow_file_ref: cow_file_ref.clone() },
                    Provider::AllocatedShared { .. }  => Provider::AllocatedShared { is_pinned_userscheme_borrow: false },
                    Provider::PhysBorrowed { base } => Provider::PhysBorrowed { base: base.clone() },
                    Provider::FmapBorrowed { ref file_ref, .. } => Provider::FmapBorrowed { file_ref: file_ref.clone(), pin_refcount: 0 },
                }
            },
        });

        let middle_page_offset = before_grant.as_ref().map_or(0, |g| g.info.page_count);

        match self.info.provider {
            Provider::PhysBorrowed { ref mut base } => *base = base.next_by(middle_page_offset),
            Provider::FmapBorrowed { ref mut file_ref, .. } | Provider::Allocated { cow_file_ref: Some(ref mut file_ref) } => file_ref.base_offset += middle_page_offset * PAGE_SIZE,
            Provider::Allocated { cow_file_ref: None } | Provider::AllocatedShared { .. } | Provider::External { .. } => (),
        }


        let after_grant = after_span.map(|span| Grant {
            base: span.base,
            info: GrantInfo {
                flags: self.info.flags,
                mapped: self.info.mapped,
                page_count: span.count,
                provider: match self.info.provider {
                    Provider::Allocated { cow_file_ref: None } => Provider::Allocated { cow_file_ref: None },
                    Provider::AllocatedShared { .. } => Provider::AllocatedShared { is_pinned_userscheme_borrow: false },
                    Provider::Allocated { cow_file_ref: Some(ref file_ref) } => Provider::Allocated { cow_file_ref: Some(GrantFileRef {
                        base_offset: file_ref.base_offset + this_span.count * PAGE_SIZE,
                        description: Arc::clone(&file_ref.description),
                    })},
                    Provider::External { ref address_space, src_base, .. } => Provider::External {
                        address_space: Arc::clone(address_space),
                        src_base,
                        is_pinned_userscheme_borrow: false,
                    },

                    Provider::PhysBorrowed { base } => Provider::PhysBorrowed { base: base.next_by(this_span.count) },
                    Provider::FmapBorrowed { ref file_ref, .. } => Provider::FmapBorrowed {
                        file_ref: GrantFileRef {
                            base_offset: file_ref.base_offset + this_span.count * PAGE_SIZE,
                            description: Arc::clone(&file_ref.description),
                        },
                        pin_refcount: 0,
                    }, 
                }
            },
        });

        self.base = this_span.base;
        self.info.page_count = this_span.count;

        Some((before_grant, self, after_grant))
    }
}
impl GrantInfo {
    pub fn is_pinned(&self) -> bool {
        matches!(self.provider,
            Provider::External { is_pinned_userscheme_borrow: true, .. }
                | Provider::AllocatedShared { is_pinned_userscheme_borrow: true, .. }
                | Provider::FmapBorrowed { pin_refcount: 1.., .. }
        )
    }
    pub fn unpin(&mut self) {
        if let Provider::External { ref mut is_pinned_userscheme_borrow, .. } | Provider::AllocatedShared { ref mut is_pinned_userscheme_borrow, .. } = self.provider {
            *is_pinned_userscheme_borrow = false;
        }
    }

    pub fn flags(&self) -> PageFlags<RmmA> {
        self.flags
    }
    pub fn page_count(&self) -> usize {
        self.page_count
    }
    pub fn can_have_flags(&self, flags: MapFlags) -> bool {
        // TODO: read
        let is_downgrade = (self.flags.has_write() || !flags.contains(MapFlags::PROT_WRITE)) && (self.flags.has_execute() || !flags.contains(MapFlags::PROT_EXEC));

        match self.provider {
            Provider::Allocated { .. } => true,
            _ => is_downgrade,
        }
    }

    pub fn can_be_merged_if_adjacent(&self, with: &Self) -> bool {
        if self.mapped != with.mapped || self.flags.data() != with.flags.data() {
            return false;
        }

        match (&self.provider, &with.provider) {
            //(Provider::PhysBorrowed { base: ref lhs }, Provider::PhysBorrowed { base: ref rhs }) => lhs.next_by(self.page_count) == rhs.clone(),
            // TODO: Add merge function that merges the page array.
            //(Provider::Allocated { .. }, Provider::Allocated { .. }) => true,
            //(Provider::External { address_space: ref lhs_space, src_base: ref lhs_base, cow: lhs_cow, .. }, Provider::External { address_space: ref rhs_space, src_base: ref rhs_base, cow: rhs_cow, .. }) => Arc::ptr_eq(lhs_space, rhs_space) && lhs_cow == rhs_cow && lhs_base.next_by(self.page_count) == rhs_base.clone(),

            _ => false,
        }
    }
    pub fn grant_flags(&self) -> GrantFlags {
        let mut flags = GrantFlags::empty();
        // TODO: has_read
        flags.set(GrantFlags::GRANT_READ, true);

        flags.set(GrantFlags::GRANT_WRITE, self.flags.has_write());
        flags.set(GrantFlags::GRANT_EXEC, self.flags.has_execute());

        // TODO: Set GRANT_LAZY

        match self.provider {
            Provider::External { is_pinned_userscheme_borrow, .. } => {
                flags.set(GrantFlags::GRANT_PINNED, is_pinned_userscheme_borrow);
                flags |= GrantFlags::GRANT_SHARED;
            }
            Provider::Allocated { ref cow_file_ref } => {
                // !GRANT_SHARED is equivalent to "GRANT_PRIVATE"
                flags.set(GrantFlags::GRANT_SCHEME, cow_file_ref.is_some());
            }
            Provider::AllocatedShared { is_pinned_userscheme_borrow } => {
                flags |= GrantFlags::GRANT_SHARED;
                flags.set(GrantFlags::GRANT_PINNED, is_pinned_userscheme_borrow);
            }
            Provider::PhysBorrowed { .. } => {
                flags |= GrantFlags::GRANT_SHARED | GrantFlags::GRANT_PHYS;
            }
            Provider::FmapBorrowed { .. } => {
                flags |= GrantFlags::GRANT_SHARED | GrantFlags::GRANT_SCHEME;
            }
        }

        flags
    }
    pub fn file_ref(&self) -> Option<&GrantFileRef> {
        // TODO: This would be bad for PhysBorrowed head/tail buffers, but otherwise the physical
        // base address could be included in offset, for PhysBorrowed.
        if let Provider::FmapBorrowed { ref file_ref, .. } | Provider::Allocated { cow_file_ref: Some(ref file_ref) } = self.provider {
            Some(file_ref)
        } else {
            None
        }
    }
}

impl Drop for GrantInfo {
    #[track_caller]
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

impl Drop for AddrSpace {
    fn drop(&mut self) {
        for grant in core::mem::take(&mut self.grants).into_iter() {
            // TODO: Optimize away clearing the actual page tables? Since this address space is no
            // longer arc-rwlock wrapped, it cannot be referenced `External`ly by borrowing grants,
            // so it should suffice to iterate over PageInfos and decrement and maybe deallocate
            // the underlying pages (and send some funmaps).
            let res = grant.unmap(&mut self.table.utable, ());

            let _ = res.unmap();
        }
    }
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
    use crate::paging::KernelMapper;

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
    use crate::paging::KernelMapper;

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
#[derive(Clone, Copy, PartialEq)]
pub enum AccessMode {
    Read,
    Write,
    InstrFetch,
}

#[derive(Debug)]
pub enum PfError {
    Segv,
    Oom,
    NonfatalInternalError,
    // TODO: Handle recursion limit by mapping a zeroed page? Or forbid borrowing borrowed memory,
    // and ensure pages are mapped at grant time?
    RecursionLimitExceeded,
}

fn cow(old_frame: Frame, old_info: &PageInfo, initial_ref_kind: RefKind) -> Result<Frame, PfError> {
    assert_ne!(old_info.refcount(), RefCount::Zero);

    if old_info.refcount() == RefCount::One {
        old_info.add_ref(initial_ref_kind).expect("must succeed, knows current value");
        return Ok(old_frame);
    }

    let new_frame = init_frame(match initial_ref_kind {
        RefKind::Cow => RefCount::One,
        RefKind::Shared => RefCount::Shared(NonZeroUsize::new(2).unwrap()),
    })?;

    // TODO: omit this step if old_frame == the_zeroed_frame()
    if old_frame != the_zeroed_frame().0 {
        unsafe { copy_frame_to_frame_directly(new_frame, old_frame); }
    }

    let _ = old_info.remove_ref();

    Ok(new_frame)
}

pub fn init_frame(init_rc: RefCount) -> Result<Frame, PfError> {
    let new_frame = crate::memory::allocate_frames(1).ok_or(PfError::Oom)?;
    let page_info = get_page_info(new_frame).unwrap_or_else(|| panic!("all allocated frames need an associated page info, {:?} didn't", new_frame));
    assert_eq!(page_info.refcount(), RefCount::Zero);
    page_info.refcount.store(init_rc.to_raw(), Ordering::Relaxed);

    Ok(new_frame)
}

fn map_zeroed(mapper: &mut PageMapper, page: Page, page_flags: PageFlags<RmmA>, _writable: bool) -> Result<Frame, PfError> {
    let new_frame = init_frame(RefCount::One)?;

    unsafe {
        mapper.map_phys(page.start_address(), new_frame.start_address(), page_flags).ok_or(PfError::Oom)?.ignore();
    }

    Ok(new_frame)
}

pub unsafe fn copy_frame_to_frame_directly(dst: Frame, src: Frame) {
    // Optimized exact-page-size copy function?

    // TODO: For new frames, when the kernel's linear phys=>virt mappings are 4k, this is almost
    // guaranteed to cause either one (or two) TLB misses.

    let dst = unsafe { RmmA::phys_to_virt(dst.start_address()).data() as *mut u8 };
    let src = unsafe { RmmA::phys_to_virt(src.start_address()).data() as *const u8 };

    unsafe {
        dst.copy_from_nonoverlapping(src, PAGE_SIZE);
    }
}

pub fn try_correcting_page_tables(faulting_page: Page, access: AccessMode) -> Result<(), PfError> {
    let Ok(addr_space_lock) = AddrSpace::current() else {
        log::debug!("User page fault without address space being set.");
        return Err(PfError::Segv);
    };

    let lock = &addr_space_lock;
    let (_, flush, _) = correct_inner(lock, lock.write(), faulting_page, access, 0)?;

    flush.flush();

    Ok(())
}
fn correct_inner<'l>(addr_space_lock: &'l Arc<RwLock<AddrSpace>>, mut addr_space_guard: RwLockWriteGuard<'l, AddrSpace>, faulting_page: Page, access: AccessMode, recursion_level: u32) -> Result<(Frame, PageFlush<RmmA>, RwLockWriteGuard<'l, AddrSpace>), PfError> {
    let mut addr_space = &mut *addr_space_guard;

    let Some((grant_base, grant_info)) = addr_space.grants.contains(faulting_page) else {
        log::debug!("Lacks grant");
        return Err(PfError::Segv);
    };

    let pages_from_grant_start = faulting_page.offset_from(grant_base);

    let grant_flags = grant_info.flags();
    match access {
        // TODO: has_read
        AccessMode::Read => (),

        AccessMode::Write if !grant_flags.has_write() => {
            log::debug!("Instuction fetch, but grant was not PROT_WRITE.");
            return Err(PfError::Segv);
        }
        AccessMode::InstrFetch if !grant_flags.has_execute() => {
            log::debug!("Instuction fetch, but grant was not PROT_EXEC.");
            return Err(PfError::Segv);
        }

        _ => (),
    }

    // By now, the memory at the faulting page is actually valid, but simply not yet mapped, either
    // at all, or with the required flags.

    let faulting_frame_opt = addr_space.table.utable
        .translate(faulting_page.start_address())
        .map(|(phys, _page_flags)| Frame::containing_address(phys));
    let faulting_pageinfo_opt = faulting_frame_opt.map(|frame| (frame, get_page_info(frame)));

    // TODO: Aligned readahead? AMD Zen3+ CPUs can smash 4 4k pages that are 16k-aligned, into a
    // single TLB entry, thus emulating 16k pages albeit with higher page table overhead. With the
    // correct madvise information, allocating 4 contiguous pages and mapping them together, might
    // be a useful future optimization.
    //
    // TODO: Readahead backwards, i.e. MAP_GROWSDOWN.

    let mut allow_writable = true;

    let mut debug = false;

    let frame = match grant_info.provider {
        Provider::Allocated { .. } | Provider::AllocatedShared { .. } if access == AccessMode::Write => {
            match faulting_pageinfo_opt {
                Some((_, None)) => unreachable!("allocated page needs frame to be valid"),
                Some((frame, Some(info))) => {
                    if info.allows_writable() {
                        frame
                    } else {
                        cow(frame, info, RefKind::Cow)?
                    }
                },
                _ => map_zeroed(&mut addr_space.table.utable, faulting_page, grant_flags, true)?,
            }
        }

        Provider::Allocated { .. } | Provider::AllocatedShared { .. } => {
            match faulting_pageinfo_opt {
                Some((_, None)) => unreachable!("allocated page needs frame to be valid"),

                // TODO: Can this match arm even be reached? In other words, can the TLB cache
                // remember that pages are not present?
                Some((frame, Some(page_info))) => {
                    // Keep in mind that allow_writable must always be true if this code is reached
                    // for AllocatedShared, since shared pages cannot be mapped lazily (without
                    // using AddrSpace backrefs).
                    allow_writable = page_info.allows_writable();

                    frame
                }

                None => {
                    // TODO: the zeroed page first, readonly?
                    map_zeroed(&mut addr_space.table.utable, faulting_page, grant_flags, false)?
                }
            }
        }
        Provider::PhysBorrowed { base } => {
            base.next_by(pages_from_grant_start)
        }
        Provider::External { address_space: ref foreign_address_space, src_base, .. } => {
            debug = true;

            let foreign_address_space = Arc::clone(foreign_address_space);

            if Arc::ptr_eq(addr_space_lock, &foreign_address_space) {
                return Err(PfError::NonfatalInternalError);
            }

            let mut guard = foreign_address_space.upgradeable_read();
            let src_page = src_base.next_by(pages_from_grant_start);

            if let Some(_) = guard.grants.contains(src_page) {
                let src_frame = if let Some((phys, _)) = guard.table.utable.translate(src_page.start_address()) {
                    Frame::containing_address(phys)
                } else {
                    // Grant was valid (TODO check), but we need to correct the underlying page.
                    // TODO: Access mode

                    // TODO: Reasonable maximum?
                    let new_recursion_level = recursion_level.checked_add(1).filter(|new_lvl| *new_lvl < 16).ok_or(PfError::RecursionLimitExceeded)?;

                    drop(guard);
                    drop(addr_space_guard);

                    let ext_addrspace = &foreign_address_space;
                    let (frame, _, _) = {
                        let g = ext_addrspace.write();
                        correct_inner(ext_addrspace, g, src_page, AccessMode::Read, new_recursion_level)?
                    };

                    addr_space_guard = addr_space_lock.write();
                    addr_space = &mut *addr_space_guard;
                    guard = foreign_address_space.upgradeable_read();

                    frame
                };

                let info = get_page_info(src_frame).expect("all allocated frames need a PageInfo");

                match info.add_ref(RefKind::Shared) {
                    Ok(()) => src_frame,
                    Err(AddRefError::RcOverflow) => return Err(PfError::Oom),
                    Err(AddRefError::CowToShared) => {
                        let new_frame = cow(src_frame, info, RefKind::Shared)?;

                        let mut guard = RwLockUpgradableGuard::upgrade(guard);

                        // TODO: flusher
                        unsafe {
                            guard.table.utable.remap_with_full(src_page.start_address(), |_, f| (new_frame.start_address(), f));
                        }

                        new_frame
                    }
                    Err(AddRefError::SharedToCow) => unreachable!(),
                }
            } else {
                // Grant did not exist, but we did own a Provider::External mapping, and cannot
                // simply let the current context fail. TODO: But all borrowed memory shouldn't
                // really be lazy though? TODO: Should a grant be created?

                let mut guard = RwLockUpgradableGuard::upgrade(guard);

                // TODO: Should this be called?
                map_zeroed(&mut guard.table.utable, src_page, grant_flags, access == AccessMode::Write)?
            }
        }
        // TODO: NonfatalInternalError if !MAP_LAZY and this page fault occurs.

        Provider::FmapBorrowed { ref file_ref, .. } => {
            let file_ref = file_ref.clone();
            let flags = map_flags(grant_info.flags());
            drop(addr_space_guard);

            let (scheme_id, scheme_number) = match file_ref.description.read() {
                ref desc => (desc.scheme, desc.number),
            };
            let user_inner = scheme::schemes()
                .get(scheme_id).and_then(|s| s.as_user_inner().transpose().ok().flatten())
                .ok_or(PfError::Segv)?;

            let offset = file_ref.base_offset as u64 + (pages_from_grant_start * PAGE_SIZE) as u64;
            user_inner.request_fmap(scheme_number, offset, 1, flags).unwrap();

            let context_lock = super::current().map_err(|_| PfError::NonfatalInternalError)?;
            context_lock.write().hard_block(HardBlockedReason::AwaitingMmap { file_ref });

            unsafe { super::switch(); }

            let frame = context_lock.write().fmap_ret.take().ok_or(PfError::NonfatalInternalError)?;

            addr_space_guard = addr_space_lock.write();
            addr_space = &mut *addr_space_guard;

            log::info!("Got frame {:?} from external fmap", frame);

            frame
        }
    };

    if super::context_id().into() == 3 && debug {
        //log::info!("Correcting {:?} => {:?} (base {:?} info {:?})", faulting_page, frame, grant_base, grant_info);
    }
    let new_flags = grant_flags.write(grant_flags.has_write() && allow_writable);
    let Some(flush) = (unsafe { addr_space.table.utable.map_phys(faulting_page.start_address(), frame.start_address(), new_flags) }) else {
        // TODO
        return Err(PfError::Oom);
    };

    Ok((frame, flush, addr_space_guard))
}

#[derive(Debug)]
pub enum MmapMode {
    Cow,
    Shared,
}

pub struct BorrowedFmapSource<'a> {
    pub src_base: Page,
    pub mode: MmapMode,
    // TODO: There should be a method that obtains the lock from the guard.
    pub addr_space_lock: &'a Arc<RwLock<AddrSpace>>,
    pub addr_space_guard: RwLockWriteGuard<'a, AddrSpace>,
}

pub fn handle_notify_files(notify_files: Vec<UnmapResult>) {
    for file in notify_files {
        let _ = file.unmap();
    }
}

pub enum CopyMappingsMode {
    Owned { cow_file_ref: Option<GrantFileRef> },
    Borrowed,
}
