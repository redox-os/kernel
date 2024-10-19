use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use arrayvec::ArrayVec;
use core::{
    cmp,
    fmt::Debug,
    num::NonZeroUsize,
    sync::atomic::{AtomicU32, Ordering},
};
use rmm::{Arch as _, PageFlush};
use spin::{RwLock, RwLockReadGuard, RwLockUpgradableGuard, RwLockWriteGuard};
use syscall::{error::*, flag::MapFlags, GrantFlags, MunmapFlags};

use crate::{
    arch::paging::PAGE_SIZE,
    context::arch::setup_new_utable,
    cpu_set::LogicalCpuSet,
    memory::{
        deallocate_frame, deallocate_p2frame, get_page_info, init_frame, the_zeroed_frame,
        AddRefError, Enomem, Frame, PageInfo, RaiiFrame, RefCount, RefKind,
    },
    paging::{Page, PageFlags, PageMapper, RmmA, TableKind, VirtualAddress},
    percpu::PercpuBlock,
    scheme::{self, KernelSchemes},
};

use super::{context::HardBlockedReason, file::FileDescription};

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
    if page_flags.has_write() {
        flags |= MapFlags::PROT_WRITE;
    }
    if page_flags.has_execute() {
        flags |= MapFlags::PROT_EXEC;
    }
    flags
}

pub struct UnmapResult {
    pub file_desc: Option<GrantFileRef>,
    pub size: usize,
    pub flags: MunmapFlags,
}
impl UnmapResult {
    pub fn unmap(mut self) -> Result<()> {
        let Some(GrantFileRef {
            base_offset,
            description,
        }) = self.file_desc.take()
        else {
            return Ok(());
        };

        let (scheme_id, number) = match description.write() {
            ref desc => (desc.scheme, desc.number),
        };

        let funmap_result = scheme::schemes()
            .get(scheme_id)
            .cloned()
            .ok_or(Error::new(ENODEV))
            .and_then(|scheme| scheme.kfunmap(number, base_offset, self.size, self.flags));

        if let Ok(fd) = Arc::try_unwrap(description) {
            fd.into_inner().try_close()?;
        }
        funmap_result?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct AddrSpaceWrapper {
    inner: RwLock<AddrSpace>,
    pub tlb_ack: AtomicU32,
}
impl AddrSpaceWrapper {
    pub fn new() -> Result<Arc<Self>> {
        Arc::try_new(Self {
            inner: RwLock::new(AddrSpace::new()?),
            tlb_ack: AtomicU32::new(0),
        })
        .map_err(|_| Error::new(ENOMEM))
    }
    pub fn acquire_read(&self) -> RwLockReadGuard<'_, AddrSpace> {
        let my_percpu = PercpuBlock::current();

        loop {
            match self.inner.try_read() {
                Some(g) => return g,
                None => {
                    my_percpu.maybe_handle_tlb_shootdown();
                    core::hint::spin_loop();
                }
            }
        }
    }
    pub fn acquire_upgradeable_read(&self) -> RwLockUpgradableGuard<'_, AddrSpace> {
        let my_percpu = PercpuBlock::current();

        loop {
            match self.inner.try_upgradeable_read() {
                Some(g) => return g,
                None => {
                    my_percpu.maybe_handle_tlb_shootdown();
                    core::hint::spin_loop();
                }
            }
        }
    }
    pub fn acquire_write(&self) -> RwLockWriteGuard<'_, AddrSpace> {
        let my_percpu = PercpuBlock::current();

        loop {
            match self.inner.try_write() {
                Some(g) => return g,
                None => {
                    my_percpu.maybe_handle_tlb_shootdown();
                    core::hint::spin_loop();
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct AddrSpace {
    pub table: Table,
    pub grants: UserGrants,
    pub used_by: LogicalCpuSet,
    /// Lowest offset for mmap invocations where the user has not already specified the offset
    /// (using MAP_FIXED/MAP_FIXED_NOREPLACE). Cf. Linux's `/proc/sys/vm/mmap_min_addr`, but with
    /// the exception that we have a memory safe kernel which doesn't have to protect itself
    /// against null pointers, so fixed mmaps to address zero are still allowed.
    pub mmap_min: usize,
}
impl AddrSpaceWrapper {
    /// Attempt to clone an existing address space so that all mappings are copied (CoW).
    pub fn try_clone(&self) -> Result<Arc<AddrSpaceWrapper>> {
        let mut guard = self.acquire_write();
        let guard = &mut *guard;

        let mut new_arc = AddrSpaceWrapper::new()?;

        let new =
            Arc::get_mut(&mut new_arc).expect("expected new address space Arc not to be aliased");

        let this_mapper = &mut guard.table.utable;
        let mut this_flusher = Flusher::with_cpu_set(&mut guard.used_by, &self.tlb_ack);

        for (grant_base, grant_info) in guard.grants.iter() {
            let new_grant = match grant_info.provider {
                // No, your temporary UserScheme mappings will not be kept across forks.
                Provider::External {
                    is_pinned_userscheme_borrow: true,
                    ..
                }
                | Provider::AllocatedShared {
                    is_pinned_userscheme_borrow: true,
                    ..
                } => continue,

                // No, physically contiguous driver memory won't either.
                Provider::Allocated {
                    phys_contiguous: true,
                    ..
                } => continue,

                Provider::PhysBorrowed { base } => Grant::physmap(
                    base.clone(),
                    PageSpan::new(grant_base, grant_info.page_count),
                    grant_info.flags,
                    &mut new.inner.get_mut().table.utable,
                    &mut NopFlusher,
                )?,
                Provider::Allocated {
                    ref cow_file_ref,
                    phys_contiguous: false,
                } => Grant::copy_mappings(
                    grant_base,
                    grant_base,
                    grant_info.page_count,
                    grant_info.flags,
                    this_mapper,
                    &mut new.inner.get_mut().table.utable,
                    &mut this_flusher,
                    &mut NopFlusher,
                    CopyMappingsMode::Owned {
                        cow_file_ref: cow_file_ref.clone(),
                    },
                )?,
                // TODO: Merge Allocated and AllocatedShared, and make CopyMappingsMode a field?
                Provider::AllocatedShared {
                    is_pinned_userscheme_borrow: false,
                } => Grant::copy_mappings(
                    grant_base,
                    grant_base,
                    grant_info.page_count,
                    grant_info.flags,
                    this_mapper,
                    &mut new.inner.get_mut().table.utable,
                    &mut this_flusher,
                    &mut NopFlusher,
                    CopyMappingsMode::Borrowed,
                )?,

                // MAP_SHARED grants are retained by reference, across address space clones (the
                // "fork" analogue from monolithic kernels).
                Provider::External {
                    ref address_space,
                    src_base,
                    ..
                } => Grant::borrow_grant(
                    Arc::clone(&address_space),
                    src_base,
                    grant_base,
                    grant_info,
                    &mut new.inner.get_mut().table.utable,
                    &mut NopFlusher,
                    false,
                )?,
                Provider::FmapBorrowed { .. } => continue,
            };

            new.inner.get_mut().grants.insert(new_grant);
        }
        Ok(new_arc)
    }
    pub fn mprotect(&self, requested_span: PageSpan, flags: MapFlags) -> Result<()> {
        let mut guard = self.acquire_write();
        let guard = &mut *guard;

        let mapper = &mut guard.table.utable;
        let mut flusher = Flusher::with_cpu_set(&mut guard.used_by, &self.tlb_ack);

        // TODO: Remove allocation (might require BTreeMap::set_key or interior mutability).
        let regions = guard
            .grants
            .conflicts(requested_span)
            .map(|(base, info)| {
                if info.is_pinned() {
                    Err(Error::new(EBUSY))
                } else {
                    Ok(PageSpan::new(base, info.page_count))
                }
            })
            .collect::<Vec<_>>();

        for grant_span_res in regions {
            let grant_span = grant_span_res?;

            let grant = guard
                .grants
                .remove(grant_span.base)
                .expect("grant cannot magically disappear while we hold the lock!");
            //log::info!("Mprotecting {:#?} to {:#?} in {:#?}", grant, flags, grant_span);
            let intersection = grant_span.intersection(requested_span);

            let (before, mut grant, after) = grant
                .extract(intersection)
                .expect("failed to extract grant");
            //log::info!("Sliced into\n\n{:#?}\n\n{:#?}\n\n{:#?}", before, grant, after);

            if let Some(before) = before {
                guard.grants.insert(before);
            }
            if let Some(after) = after {
                guard.grants.insert(after);
            }

            if !grant.info.can_have_flags(flags) {
                guard.grants.insert(grant);
                return Err(Error::new(EACCES));
            }

            let new_flags = grant
                .info
                .flags()
                // TODO: Require a capability in order to map executable memory?
                .execute(flags.contains(MapFlags::PROT_EXEC))
                .write(flags.contains(MapFlags::PROT_WRITE));

            // TODO: Allow enabling/disabling read access on architectures which allow it. On
            // x86_64 with protection keys (although only enforced by userspace), and AArch64 (I
            // think), execute-only memory is also supported.

            grant.remap(mapper, &mut flusher, new_flags);
            //log::info!("Mprotect grant became {:#?}", grant);
            guard.grants.insert(grant);
        }
        Ok(())
    }
    #[must_use = "needs to notify files"]
    pub fn munmap(&self, requested_span: PageSpan, unpin: bool) -> Result<Vec<UnmapResult>> {
        let mut guard = self.acquire_write();
        let guard = &mut *guard;

        let mut flusher = Flusher::with_cpu_set(&mut guard.used_by, &self.tlb_ack);
        AddrSpace::munmap_inner(
            &mut guard.grants,
            &mut guard.table.utable,
            &mut flusher,
            requested_span,
            unpin,
        )
    }
    pub fn r#move(
        &self,
        mut src_opt: Option<(&AddrSpaceWrapper, &mut AddrSpace)>,
        src_span: PageSpan,
        requested_dst_base: Option<Page>,
        new_page_count: usize,
        new_flags: MapFlags,
        notify_files: &mut Vec<UnmapResult>,
    ) -> Result<Page> {
        let dst_lock = self;
        let mut dst = dst_lock.acquire_write();
        let dst = &mut *dst;

        let mut src_owned_opt = src_opt.as_mut().map(|(aw, a)| {
            (
                &mut a.grants,
                &mut a.table.utable,
                Flusher::with_cpu_set(&mut a.used_by, &aw.tlb_ack),
            )
        });
        let mut src_opt = src_owned_opt
            .as_mut()
            .map(|(g, m, f)| (&mut *g, &mut *m, &mut *f));
        let mut dst_flusher = Flusher::with_cpu_set(&mut dst.used_by, &dst_lock.tlb_ack);

        let dst_base = match requested_dst_base {
            Some(base) if new_flags.contains(MapFlags::MAP_FIXED_NOREPLACE) => {
                if dst
                    .grants
                    .conflicts(PageSpan::new(base, new_page_count))
                    .next()
                    .is_some()
                {
                    return Err(Error::new(EEXIST));
                }

                base
            }
            Some(base) if new_flags.contains(MapFlags::MAP_FIXED) => {
                let unpin = false;
                notify_files.append(&mut AddrSpace::munmap_inner(
                    &mut dst.grants,
                    &mut dst.table.utable,
                    &mut dst_flusher,
                    PageSpan::new(base, new_page_count),
                    unpin,
                )?);

                base
            }
            _ => {
                dst.grants
                    .find_free(dst.mmap_min, cmp::max(new_page_count, src_span.count))
                    .ok_or(Error::new(ENOMEM))?
                    .base
            }
        };

        let (src_grants, src_mapper, src_flusher) = src_opt.as_mut().map_or(
            (&mut dst.grants, &mut dst.table.utable, &mut dst_flusher),
            |(g, m, f)| (&mut *g, &mut *m, &mut *f),
        );

        if src_grants
            .conflicts(src_span)
            .any(|(_, g)| !g.can_extract(false))
        {
            return Err(Error::new(EBUSY));
        }
        if src_grants
            .conflicts(src_span)
            .any(|(_, g)| !g.can_have_flags(new_flags))
        {
            return Err(Error::new(EPERM));
        }
        if PageSpan::new(dst_base, new_page_count).intersects(src_span) {
            return Err(Error::new(EBUSY));
        }

        if new_page_count < src_span.count {
            let unpin = false;
            notify_files.append(&mut AddrSpace::munmap_inner(
                src_grants,
                src_mapper,
                src_flusher,
                PageSpan::new(
                    src_span.base.next_by(new_page_count),
                    src_span.count - new_page_count,
                ),
                unpin,
            )?);
        }

        let mut remaining_src_span = PageSpan::new(src_span.base, new_page_count);

        let to_remap = src_grants
            .conflicts(remaining_src_span)
            .map(|(b, _)| b)
            .collect::<Vec<_>>();

        let mut prev_grant_end = src_span.base;

        //while let Some(grant_base) = next(src_opt.as_mut().map(|s| &mut **s), dst, remaining_src_span) {
        for grant_base in to_remap {
            if prev_grant_end < grant_base {
                let hole_page_count = grant_base.offset_from(prev_grant_end);
                let hole_span = PageSpan::new(
                    dst_base.next_by(prev_grant_end.offset_from(src_span.base)),
                    hole_page_count,
                );
                dst.grants.insert(Grant::zeroed(
                    hole_span,
                    page_flags(new_flags),
                    &mut dst.table.utable,
                    &mut dst_flusher,
                    false,
                )?);
            }

            let (src_grants, _, _) = src_opt.as_mut().map_or(
                (&mut dst.grants, &mut dst.table.utable, &mut dst_flusher),
                |(g, m, f)| (&mut *g, &mut *m, &mut *f),
            );
            let grant = src_grants
                .remove(grant_base)
                .expect("grant cannot disappear");
            let grant_span = PageSpan::new(grant.base, grant.info.page_count());
            let (before, middle, after) = grant
                .extract(remaining_src_span.intersection(grant_span))
                .expect("called intersect(), must succeed");

            if let Some(before) = before {
                src_grants.insert(before);
            }
            if let Some(after) = after {
                src_grants.insert(after);
            }

            let dst_grant_base = dst_base.next_by(middle.base.offset_from(src_span.base));
            let middle_span = middle.span();

            let mut src_opt = src_opt
                .as_mut()
                .map(|(g, m, f)| (&mut *g, &mut *m, &mut *f));

            dst.grants.insert(match src_opt.as_mut() {
                Some((_, other_mapper, other_flusher)) => middle.transfer(
                    dst_grant_base,
                    page_flags(new_flags),
                    other_mapper,
                    Some(&mut dst.table.utable),
                    other_flusher,
                    &mut dst_flusher,
                )?,
                None => middle.transfer(
                    dst_grant_base,
                    page_flags(new_flags),
                    &mut dst.table.utable,
                    None,
                    &mut dst_flusher,
                    &mut NopFlusher,
                )?,
            });

            prev_grant_end = middle_span.base.next_by(middle_span.count);
            let pages_advanced = prev_grant_end.offset_from(remaining_src_span.base);
            remaining_src_span =
                PageSpan::new(prev_grant_end, remaining_src_span.count - pages_advanced);
        }

        if prev_grant_end < src_span.base.next_by(new_page_count) {
            let last_hole_span = PageSpan::new(
                dst_base.next_by(prev_grant_end.offset_from(src_span.base)),
                new_page_count - prev_grant_end.offset_from(src_span.base),
            );
            dst.grants.insert(Grant::zeroed(
                last_hole_span,
                page_flags(new_flags),
                &mut dst.table.utable,
                &mut dst_flusher,
                false,
            )?);
        }

        Ok(dst_base)
    }
    /// Borrows a page from user memory, requiring that the frame be Allocated and read/write. This
    /// is intended to be used for user-kernel shared memory.
    pub fn borrow_frame_enforce_rw_allocated(self: &Arc<Self>, page: Page) -> Result<RaiiFrame> {
        let mut guard = self.acquire_write();

        let (_start_page, info) = guard.grants.contains(page).ok_or(Error::new(EINVAL))?;

        if !info.can_have_flags(MapFlags::PROT_READ | MapFlags::PROT_WRITE) {
            return Err(Error::new(EPERM));
        }
        if !matches!(info.provider, Provider::Allocated { .. }) {
            return Err(Error::new(EPERM));
        }

        let frame = if let Some((f, fl)) = guard.table.utable.translate(page.start_address())
            && fl.has_write()
        {
            Frame::containing(f)
        } else {
            let (frame, flush, new_guard) = correct_inner(self, guard, page, AccessMode::Write, 0)
                .map_err(|_| Error::new(ENOMEM))?;
            flush.flush();
            guard = new_guard;

            frame
        };

        let frame = match get_page_info(frame)
            .expect("missing page info for Allocated grant")
            .add_ref(RefKind::Shared)
        {
            Ok(_) => Ok(unsafe { RaiiFrame::new_unchecked(frame) }),
            Err(AddRefError::RcOverflow) => Err(Error::new(ENOMEM)),
            Err(AddRefError::SharedToCow) => unreachable!(),
            Err(AddRefError::CowToShared) => unreachable!(
                "if it was CoW, it was read-only, but in that case we already called correct_inner"
            ),
        };
        drop(guard);

        frame
    }
}
impl AddrSpace {
    pub fn current() -> Result<Arc<AddrSpaceWrapper>> {
        PercpuBlock::current()
            .current_addrsp
            .borrow()
            .clone()
            .ok_or(Error::new(ESRCH))
    }

    pub fn new() -> Result<Self> {
        Ok(Self {
            grants: UserGrants::new(),
            table: setup_new_utable()?,
            mmap_min: MMAP_MIN_DEFAULT,
            used_by: LogicalCpuSet::empty(),
        })
    }
    fn munmap_inner(
        this_grants: &mut UserGrants,
        this_mapper: &mut PageMapper,
        this_flusher: &mut Flusher,
        mut requested_span: PageSpan,
        unpin: bool,
    ) -> Result<Vec<UnmapResult>> {
        let mut notify_files = Vec::new();

        let next = |grants: &mut UserGrants, span: PageSpan| {
            grants
                .conflicts(span)
                .map(|(base, info)| {
                    if info.is_pinned() && !unpin {
                        Err(Error::new(EBUSY))
                    } else if !info.can_extract(unpin) {
                        Err(Error::new(EINVAL))
                    } else {
                        Ok(PageSpan::new(base, info.page_count))
                    }
                })
                .next()
        };

        while let Some(conflicting_span_res) = next(this_grants, requested_span) {
            let conflicting_span = conflicting_span_res?;

            let mut grant = this_grants
                .remove(conflicting_span.base)
                .expect("conflicting region didn't exist");
            if unpin {
                grant.info.unpin();
            }

            let intersection = conflicting_span.intersection(requested_span);

            requested_span = {
                // In the following diagrams [---> indicates a range of
                // base..base+count where the [ is at the base and > is at
                // base+count. In other words, the [ is part of the range and
                // the > is not part of the range.
                if conflicting_span.end() < requested_span.end() {
                    // [------>     conflicting_span
                    //    [-------> requested_span
                    //        [---> next requested_span
                    // or
                    //    [---->    conflicting_span
                    // [----------> requested_span
                    //         [--> next requested_span
                    PageSpan::new(
                        conflicting_span.end(),
                        requested_span.end().offset_from(conflicting_span.end()),
                    )
                } else {
                    // [----------> conflicting_span
                    //    [----->   requested_span
                    //              next requested_span
                    // or
                    //   [--------> conflicting_span
                    // [-------->   requested_span
                    //              next requested_span
                    PageSpan::empty()
                }
            };

            let (before, grant, after) = grant
                .extract(intersection)
                .expect("conflicting region shared no common parts");

            // Keep untouched regions
            if let Some(before) = before {
                this_grants.insert(before);
            }
            if let Some(after) = after {
                this_grants.insert(after);
            }

            // Remove irrelevant region
            let unmap_result = grant.unmap(this_mapper, this_flusher);

            // Notify scheme that holds grant
            if unmap_result.file_desc.is_some() {
                notify_files.push(unmap_result);
            }
        }

        Ok(notify_files)
    }
    pub fn mmap_anywhere(
        &mut self,
        dst_lock: &AddrSpaceWrapper,
        page_count: NonZeroUsize,
        flags: MapFlags,
        map: impl FnOnce(Page, PageFlags<RmmA>, &mut PageMapper, &mut Flusher) -> Result<Grant>,
    ) -> Result<Page> {
        self.mmap(dst_lock, None, page_count, flags, &mut Vec::new(), map)
    }
    pub fn mmap(
        &mut self,
        dst_lock: &AddrSpaceWrapper,
        requested_base_opt: Option<Page>,
        page_count: NonZeroUsize,
        flags: MapFlags,
        notify_files_out: &mut Vec<UnmapResult>,
        map: impl FnOnce(Page, PageFlags<RmmA>, &mut PageMapper, &mut Flusher) -> Result<Grant>,
    ) -> Result<Page> {
        debug_assert_eq!(dst_lock.inner.as_mut_ptr(), self as *mut Self);

        let selected_span = match requested_base_opt {
            // TODO: Rename MAP_FIXED+MAP_FIXED_NOREPLACE to MAP_FIXED and
            // MAP_FIXED_REPLACE/MAP_REPLACE?
            Some(requested_base) => {
                let requested_span = PageSpan::new(requested_base, page_count.get());

                if flags.contains(MapFlags::MAP_FIXED_NOREPLACE) {
                    if self.grants.conflicts(requested_span).next().is_some() {
                        return Err(Error::new(EEXIST));
                    }
                    requested_span
                } else if flags.contains(MapFlags::MAP_FIXED) {
                    let unpin = false;
                    let mut notify_files = Self::munmap_inner(
                        &mut self.grants,
                        &mut self.table.utable,
                        &mut Flusher::with_cpu_set(&mut self.used_by, &dst_lock.tlb_ack),
                        requested_span,
                        unpin,
                    )?;
                    notify_files_out.append(&mut notify_files);

                    requested_span
                } else {
                    self.grants
                        .find_free_near(self.mmap_min, page_count.get(), Some(requested_base))
                        .ok_or(Error::new(ENOMEM))?
                }
            }
            None => self
                .grants
                .find_free(self.mmap_min, page_count.get())
                .ok_or(Error::new(ENOMEM))?,
        };

        // TODO: Threads share address spaces, so not only the inactive flusher should be sending
        // out IPIs. IPIs will only be sent when downgrading mappings (i.e. when a stale TLB entry
        // will not be corrected by a page fault), and will furthermore require proper
        // synchronization.

        let grant = map(
            selected_span.base,
            page_flags(flags),
            &mut self.table.utable,
            &mut Flusher::with_cpu_set(&mut self.used_by, &dst_lock.tlb_ack),
        )?;
        self.grants.insert(grant);

        Ok(selected_span.base)
    }
}

#[derive(Debug)]
pub struct UserGrants {
    // Using a BTreeMap for it's range method.
    inner: BTreeMap<Page, GrantInfo>,
    // Using a BTreeMap for it's range method.
    holes: BTreeMap<VirtualAddress, usize>,
    // TODO: Would an additional map ordered by (size,start) to allow for O(log n) allocations be
    // beneficial?
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
    pub fn empty() -> Self {
        Self {
            base: Page::containing_address(VirtualAddress::new(0)),
            count: 0,
        }
    }
    pub fn validate_nonempty(address: VirtualAddress, size: usize) -> Option<Self> {
        Self::validate(address, size).filter(|this| !this.is_empty())
    }
    pub fn validate(address: VirtualAddress, size: usize) -> Option<Self> {
        if address.data() % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
            return None;
        }
        if address.data().saturating_add(size) > crate::USER_END_OFFSET {
            return None;
        }

        Some(Self::new(
            Page::containing_address(address),
            size / PAGE_SIZE,
        ))
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
        Some(Self::between(self.base, span.base)).filter(|reg| !reg.is_empty())
    }

    /// Returns the span from the end of the given span until the end of self.
    pub fn after(self, span: Self) -> Option<Self> {
        assert!(span.end() <= self.end());
        Some(Self::between(span.end(), self.end())).filter(|reg| !reg.is_empty())
    }
    /// Returns the span between two pages, `[start, end)`, truncating to zero if end < start.
    pub fn between(start: Page, end: Page) -> Self {
        Self::new(
            start,
            end.start_address()
                .data()
                .saturating_sub(start.start_address().data())
                / PAGE_SIZE,
        )
    }
}

impl Default for UserGrants {
    fn default() -> Self {
        Self::new()
    }
}
impl Debug for PageSpan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "[{:p}:{:p}, {} pages]",
            self.base.start_address().data() as *const u8,
            self.base
                .start_address()
                .add(self.count * PAGE_SIZE - 1)
                .data() as *const u8,
            self.count
        )
    }
}

impl UserGrants {
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
            holes: core::iter::once((VirtualAddress::new(0), crate::USER_END_OFFSET))
                .collect::<BTreeMap<_, _>>(),
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
        let start_span = start
            .map(|(base, info)| PageSpan::new(base, info.page_count))
            .unwrap_or(span);

        self.inner
            .range(start_span.base..)
            .take_while(move |(base, info)| PageSpan::new(**base, info.page_count).intersects(span))
            .map(|(base, info)| (*base, info))
    }
    // TODO: DEDUPLICATE CODE!
    pub fn conflicts_mut(
        &mut self,
        span: PageSpan,
    ) -> impl Iterator<Item = (Page, &'_ mut GrantInfo)> + '_ {
        let start = self.contains(span.base);

        // If there is a grant that contains the base page, start searching at the base of that
        // grant, rather than the requested base here.
        let start_span = start
            .map(|(base, info)| PageSpan::new(base, info.page_count))
            .unwrap_or(span);

        self.inner
            .range_mut(start_span.base..)
            .take_while(move |(base, info)| PageSpan::new(**base, info.page_count).intersects(span))
            .map(|(base, info)| (*base, info))
    }
    /// Return a free region with the specified size
    // TODO: Alignment (x86_64: 4 KiB, 2 MiB, or 1 GiB).
    // TODO: Support finding grant close to a requested address?
    pub fn find_free_near(
        &self,
        min: usize,
        page_count: usize,
        _near: Option<Page>,
    ) -> Option<PageSpan> {
        // Get first available hole, but do reserve the page starting from zero as most compiled
        // languages cannot handle null pointers safely even if they point to valid memory. If an
        // application absolutely needs to map the 0th page, they will have to do so explicitly via
        // MAP_FIXED/MAP_FIXED_NOREPLACE.
        // TODO: Allow explicitly allocating guard pages? Perhaps using mprotect or mmap with
        // PROT_NONE?

        let (hole_start, _hole_size) = self
            .holes
            .iter()
            .skip_while(|(hole_offset, hole_size)| hole_offset.data() + **hole_size <= min)
            .find(|(hole_offset, hole_size)| {
                let avail_size =
                    if hole_offset.data() <= min && min <= hole_offset.data() + **hole_size {
                        **hole_size - (min - hole_offset.data())
                    } else {
                        **hole_size
                    };
                page_count * PAGE_SIZE <= avail_size
            })?;
        // Create new region
        Some(PageSpan::new(
            Page::containing_address(VirtualAddress::new(cmp::max(hole_start.data(), min))),
            page_count,
        ))
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
                self.holes
                    .insert(end_address, prev_hole_end - end_address.data());
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
        if let Some((hole_offset, hole_size)) = holes
            .range_mut(..start_address)
            .next_back()
            .filter(|(offset, size)| offset.data() + **size == start_address.data())
        {
            *hole_size = end_address.data() - hole_offset.data() + exactly_after_size.unwrap_or(0);
        } else {
            // There was no free region directly before the to-be-freed region, however will
            // now unconditionally insert a new free region where the grant was, and add that extra
            // size if there was something after it.
            holes.insert(start_address, size + exactly_after_size.unwrap_or(0));
        }
    }
    pub fn insert(&mut self, mut grant: Grant) {
        assert!(self
            .conflicts(PageSpan::new(grant.base, grant.info.page_count))
            .next()
            .is_none());
        self.reserve(grant.base, grant.info.page_count);

        let before_region = self
            .inner
            .range(..grant.base)
            .next_back()
            .filter(|(base, info)| {
                base.next_by(info.page_count) == grant.base
                    && info.can_be_merged_if_adjacent(&grant.info)
            })
            .map(|(base, info)| (*base, info.page_count));

        let after_region = self
            .inner
            .range(grant.span().end()..)
            .next()
            .filter(|(base, info)| {
                **base == grant.base.next_by(grant.info.page_count)
                    && info.can_be_merged_if_adjacent(&grant.info)
            })
            .map(|(base, info)| (*base, info.page_count));

        if let Some((before_base, before_page_count)) = before_region {
            grant.base = before_base;
            grant.info.page_count += before_page_count;

            core::mem::forget(self.inner.remove(&before_base));
        }
        if let Some((after_base, after_page_count)) = after_region {
            grant.info.page_count += after_page_count;

            core::mem::forget(self.inner.remove(&after_base));
        }

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
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub fn into_iter(self) -> impl Iterator<Item = Grant> {
        self.inner
            .into_iter()
            .map(|(base, info)| Grant { base, info })
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
    Allocated {
        cow_file_ref: Option<GrantFileRef>,
        phys_contiguous: bool,
    },

    /// The grant is owned, but possibly shared.
    ///
    /// The pages may only be lazily initialized, if the address space has not yet been cloned (when forking).
    ///
    /// This type of grants is obtained from MAP_SHARED anonymous or `memory:` mappings, i.e.
    /// allocated memory that remains shared after address space clones.
    AllocatedShared { is_pinned_userscheme_borrow: bool },

    /// The grant is not owned, but borrowed from physical memory frames that do not belong to the
    /// frame allocator. The kernel will forbid borrowing any physical memory range, that the
    /// memory map has indicated is regular allocatable RAM.
    PhysBorrowed { base: Frame },

    /// The memory is borrowed directly from another address space.
    External {
        address_space: Arc<AddrSpaceWrapper>,
        src_base: Page,
        is_pinned_userscheme_borrow: bool,
    },

    /// The memory is MAP_SHARED borrowed from a scheme.
    ///
    /// Since the address space is not tracked here, all nonpresent pages must be present before
    /// the fmap operation completes, unless MAP_LAZY is specified. They are tracked using
    /// PageInfo, or treated as PhysBorrowed if any frame lacks a PageInfo.
    FmapBorrowed {
        file_ref: GrantFileRef,
        pin_refcount: usize,
    },
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
    pub fn allocated_shared_one_page(
        frame: Frame,
        page: Page,
        flags: PageFlags<RmmA>,
        mapper: &mut PageMapper,
        flusher: &mut Flusher,
        is_pinned: bool,
    ) -> Result<Grant> {
        let info = get_page_info(frame).expect("needs page info");

        // TODO:
        //
        // This may not necessarily hold, as even pinned memory can remain shared (e.g. proc:
        // borrow), but it would probably be possible to forbid borrowing memory there as well.
        // Maybe make it exclusive first using cow(), unless that is too expensive.
        //
        // assert_eq!(info.refcount(), RefCount::One);

        // Semantically, the page will be shared between the "context struct" and whatever
        // else.
        info.add_ref(RefKind::Shared)
            .expect("must be possible if previously Zero");

        unsafe {
            mapper
                .map_phys(page.start_address(), frame.base(), flags)
                .ok_or(Error::new(ENOMEM))?
                .ignore();

            flusher.queue(frame, None, TlbShootdownActions::NEW_MAPPING);
        }

        Ok(Grant {
            base: page,
            info: GrantInfo {
                page_count: 1,
                flags,
                mapped: true,
                provider: Provider::AllocatedShared {
                    is_pinned_userscheme_borrow: is_pinned,
                },
            },
        })
    }

    pub fn physmap(
        phys: Frame,
        span: PageSpan,
        flags: PageFlags<RmmA>,
        mapper: &mut PageMapper,
        flusher: &mut impl GenericFlusher,
    ) -> Result<Grant> {
        const MAX_EAGER_PAGES: usize = 4096;

        for i in 0..span.count {
            if let Some(info) = get_page_info(phys.next_by(i)) {
                log::warn!("Driver tried to physmap the allocator-frame {phys:?} (info {info:?})!");
                return Err(Error::new(EPERM));
            }
        }

        for (i, page) in span.pages().enumerate().take(MAX_EAGER_PAGES) {
            let frame = phys.next_by(i);
            unsafe {
                let Some(result) =
                    mapper.map_phys(page.start_address(), frame.base(), flags.write(false))
                else {
                    break;
                };
                result.ignore();

                flusher.queue(frame, None, TlbShootdownActions::NEW_MAPPING);
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
    pub fn zeroed_phys_contiguous(
        span: PageSpan,
        flags: PageFlags<RmmA>,
        mapper: &mut PageMapper,
        flusher: &mut Flusher,
    ) -> Result<Grant, Enomem> {
        if !span.count.is_power_of_two() {
            log::warn!("Attempted non-power-of-two zeroed_phys_contiguous allocation, rounding up to next power of two.");
        }

        let alloc_order = span.count.next_power_of_two().trailing_zeros();
        let base = crate::memory::allocate_p2frame(alloc_order).ok_or(Enomem)?;

        for (i, page) in span.pages().enumerate() {
            let frame = base.next_by(i);

            get_page_info(frame)
                .expect("PageInfo must exist for allocated frame")
                .refcount
                .store(RefCount::One.to_raw(), Ordering::Relaxed);

            unsafe {
                let result = mapper
                    .map_phys(page.start_address(), frame.base(), flags)
                    .expect("TODO: page table OOM");
                result.ignore();

                flusher.queue(frame, None, TlbShootdownActions::NEW_MAPPING);
            }
        }

        Ok(Grant {
            base: span.base,
            info: GrantInfo {
                page_count: span.count,
                flags,
                mapped: true,
                provider: Provider::Allocated {
                    cow_file_ref: None,
                    phys_contiguous: true,
                },
            },
        })
    }
    pub fn zeroed(
        span: PageSpan,
        flags: PageFlags<RmmA>,
        mapper: &mut PageMapper,
        flusher: &mut Flusher,
        shared: bool,
    ) -> Result<Grant, Enomem> {
        const MAX_EAGER_PAGES: usize = 16;

        let (the_frame, the_frame_info) = the_zeroed_frame();

        // TODO: Use flush_all after a certain number of pages, otherwise no

        for page in span.pages().take(MAX_EAGER_PAGES) {
            // Good thing with lazy page fault handlers, is that if we fail due to ENOMEM here, we
            // can continue and let the process face the OOM killer later.
            unsafe {
                the_frame_info
                    .add_ref(RefKind::Cow)
                    .expect("the static zeroed frame cannot be shared!");

                let Some(result) =
                    mapper.map_phys(page.start_address(), the_frame.base(), flags.write(false))
                else {
                    break;
                };
                result.ignore();
                flusher.queue(the_frame, None, TlbShootdownActions::NEW_MAPPING);
            }
        }

        Ok(Grant {
            base: span.base,
            info: GrantInfo {
                page_count: span.count,
                flags,
                mapped: true,
                provider: if shared {
                    Provider::AllocatedShared {
                        is_pinned_userscheme_borrow: false,
                    }
                } else {
                    Provider::Allocated {
                        cow_file_ref: None,
                        phys_contiguous: false,
                    }
                },
            },
        })
    }

    // XXX: borrow_grant is needed because of the borrow checker (iterator invalidation), maybe
    // borrow_grant/borrow can be abstracted somehow?
    pub fn borrow_grant(
        src_address_space_lock: Arc<AddrSpaceWrapper>,
        src_base: Page,
        dst_base: Page,
        src_info: &GrantInfo,
        _mapper: &mut PageMapper,
        _dst_flusher: &mut impl GenericFlusher,
        _eager: bool,
    ) -> Result<Grant, Enomem> {
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
                },
            },
        })
    }

    pub fn borrow_fmap(
        span: PageSpan,
        new_flags: PageFlags<RmmA>,
        file_ref: GrantFileRef,
        src: Option<BorrowedFmapSource<'_>>,
        lock: &AddrSpaceWrapper,
        mapper: &mut PageMapper,
        flusher: &mut Flusher,
    ) -> Result<Self> {
        if let Some(src) = src {
            let mut guard = src.addr_space_guard;
            let mut src_addrspace = &mut *guard;
            let mut src_flusher_state =
                Flusher::with_cpu_set(&mut src_addrspace.used_by, &lock.tlb_ack).detach();
            for dst_page in span.pages() {
                let src_page = src.src_base.next_by(dst_page.offset_from(span.base));

                let (frame, is_cow) = match src.mode {
                    MmapMode::Shared => {
                        // TODO: Error code for "scheme responded with unmapped page"?
                        let frame = match src_addrspace
                            .table
                            .utable
                            .translate(src_page.start_address())
                        {
                            Some((phys, _)) => Frame::containing(phys),
                            // TODO: ensure the correct context is hardblocked, if necessary
                            None => {
                                let (frame, _, new_guard) = correct_inner(
                                    src.addr_space_lock,
                                    guard,
                                    src_page,
                                    AccessMode::Read,
                                    0,
                                )
                                .map_err(|_| Error::new(EIO))?;
                                guard = new_guard;
                                frame
                            }
                        };

                        (frame, false)
                    }
                    MmapMode::Cow => unsafe {
                        let frame = match guard
                            .table
                            .utable
                            .remap_with(src_page.start_address(), |flags| flags.write(false))
                        {
                            Some((_, phys, _)) => Frame::containing(phys),
                            // TODO: ensure the correct context is hardblocked, if necessary
                            None => {
                                let (frame, _, new_guard) = correct_inner(
                                    src.addr_space_lock,
                                    guard,
                                    src_page,
                                    AccessMode::Read,
                                    0,
                                )
                                .map_err(|_| Error::new(EIO))?;
                                guard = new_guard;
                                frame
                            }
                        };

                        (frame, true)
                    },
                };
                src_addrspace = &mut *guard;

                let frame = if let Some(page_info) = get_page_info(frame) {
                    match page_info.add_ref(RefKind::Shared) {
                        Ok(()) => frame,
                        Err(AddRefError::CowToShared) => unsafe {
                            let CowResult {
                                new_frame: new_cow_frame,
                                old_frame,
                            } = cow(frame, page_info, RefKind::Shared)
                                .map_err(|_| Error::new(ENOMEM))?;

                            let (old_flags, _, _flush) = src_addrspace
                                .table
                                .utable
                                .remap_with_full(src_page.start_address(), |_, flags| {
                                    (new_cow_frame.base(), flags)
                                })
                                .expect("page did exist");

                            // TODO: flush.ignore() is correct, but seems to be amplifying a
                            // userspace race condition
                            //
                            //flush.ignore();

                            let mut src_flusher = Flusher {
                                active_cpus: &mut src_addrspace.used_by,
                                state: src_flusher_state,
                            };
                            src_flusher.queue(
                                frame,
                                None,
                                TlbShootdownActions::change_of_flags(old_flags, new_flags),
                            );

                            if let Some(old_frame) = old_frame {
                                src_flusher.queue(old_frame, None, TlbShootdownActions::FREE);
                            }
                            src_flusher_state = src_flusher.detach();

                            // TODO: there used to be an additional remove_ref here, was that
                            // correct?

                            new_cow_frame
                        },
                        Err(AddRefError::SharedToCow) => unreachable!(),
                        Err(AddRefError::RcOverflow) => return Err(Error::new(ENOMEM)),
                    }
                } else {
                    frame
                };

                unsafe {
                    let flush = mapper
                        .map_phys(
                            dst_page.start_address(),
                            frame.base(),
                            new_flags.write(new_flags.has_write() && !is_cow),
                        )
                        .unwrap();
                    flush.ignore();

                    flusher.queue(frame, None, TlbShootdownActions::NEW_MAPPING);
                }
            }
        }

        Ok(Self {
            base: span.base,
            info: GrantInfo {
                page_count: span.count,
                mapped: true,
                flags: new_flags,
                provider: Provider::FmapBorrowed {
                    file_ref,
                    pin_refcount: 0,
                },
            },
        })
    }

    /// Borrow all pages in the range `[src_base, src_base+page_count)` from `src_address_space`,
    /// mapping them into `[dst_base, dst_base+page_count)`. The destination pages will lazily read
    /// the page tables of the source pages, but once present in the destination address space,
    /// pages that are unmaped or moved will not be made visible to the destination address space.
    pub fn borrow(
        src_address_space_lock: Arc<AddrSpaceWrapper>,
        src_address_space: &mut AddrSpace,
        src_base: Page,
        dst_base: Page,
        page_count: usize,
        map_flags: MapFlags,
        dst_mapper: &mut PageMapper,
        dst_flusher: &mut Flusher,
        eager: bool,
        _allow_phys: bool,
        is_pinned_userscheme_borrow: bool,
    ) -> Result<Grant> {
        let flags = page_flags(map_flags);

        const MAX_EAGER_PAGES: usize = 4096;

        let src_span = PageSpan::new(src_base, page_count);
        let mut prev_span = None;

        for (src_grant_base, src_grant) in src_address_space.grants.conflicts_mut(src_span) {
            let grant_span = PageSpan::new(src_grant_base, src_grant.page_count);
            let prev_span = prev_span.replace(grant_span);

            if prev_span.is_none() && src_grant_base > src_base {
                log::warn!(
                    "Grant too far away, prev_span {:?} src_base {:?} grant base {:?} grant {:#?}",
                    prev_span,
                    src_base,
                    src_grant_base,
                    src_grant
                );
                return Err(Error::new(EINVAL));
            } else if let Some(prev) = prev_span
                && prev.end() != src_grant_base
            {
                log::warn!(
                    "Hole between grants, prev_span {:?} src_base {:?} grant base {:?} grant {:#?}",
                    prev_span,
                    src_base,
                    src_grant_base,
                    src_grant
                );
                return Err(Error::new(EINVAL));
            }

            if !src_grant.can_have_flags(map_flags) {
                return Err(Error::new(EPERM));
            }

            if let Provider::FmapBorrowed {
                ref mut pin_refcount,
                ..
            } = src_grant.provider
            {
                *pin_refcount += 1;
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
        if eager {
            for (i, page) in PageSpan::new(src_base, page_count)
                .pages()
                .enumerate()
                .take(MAX_EAGER_PAGES)
            {
                let Some((phys, _)) = src_address_space
                    .table
                    .utable
                    .translate(page.start_address())
                else {
                    continue;
                };

                let writable = match get_page_info(Frame::containing(phys)) {
                    None => true,
                    Some(i) => {
                        if i.add_ref(RefKind::Shared).is_err() {
                            continue;
                        };

                        i.allows_writable()
                    }
                };

                unsafe {
                    let flush = dst_mapper
                        .map_phys(
                            dst_base.next_by(i).start_address(),
                            phys,
                            flags.write(flags.has_write() && writable),
                        )
                        .ok_or(Error::new(ENOMEM))?;
                    flush.ignore();

                    dst_flusher.queue(
                        Frame::containing(phys),
                        None,
                        TlbShootdownActions::NEW_MAPPING,
                    );
                }
            }
        }

        Ok(Grant {
            base: dst_base,
            info: GrantInfo {
                page_count,
                flags,
                mapped: true,
                provider: Provider::External {
                    address_space: src_address_space_lock,
                    src_base,
                    is_pinned_userscheme_borrow,
                },
            },
        })
    }
    pub fn copy_mappings(
        src_base: Page,
        dst_base: Page,
        page_count: usize,
        flags: PageFlags<RmmA>,
        src_mapper: &mut PageMapper,
        dst_mapper: &mut PageMapper,
        src_flusher: &mut Flusher,
        dst_flusher: &mut impl GenericFlusher,
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
                    let Some((_, phys, flush)) = (unsafe {
                        src_mapper.remap_with(src_page.start_address(), |flags| flags.write(false))
                    }) else {
                        // Page is not mapped, let the page fault handler take care of that (initializing
                        // it to zero).
                        //
                        // TODO: If eager, allocate zeroed page if writable, or use *the* zeroed page (also
                        // for read-only)?
                        continue;
                    };
                    unsafe {
                        flush.ignore();
                    }
                    let frame = Frame::containing(phys);
                    src_flusher.queue(frame, None, TlbShootdownActions::REVOKE_WRITE);
                    frame
                }
                RefKind::Shared => {
                    if let Some((phys, _)) = src_mapper.translate(src_page.start_address()) {
                        Frame::containing(phys)
                    } else {
                        // TODO: Omit the unnecessary subsequent add_ref call.
                        let new_frame = init_frame(RefCount::One).expect("TODO: handle OOM");
                        let src_flush = unsafe {
                            src_mapper
                                .map_phys(src_page.start_address(), new_frame.base(), flags)
                                .expect("TODO: handle OOM")
                        };
                        unsafe {
                            src_flush.ignore();
                        }
                        src_flusher.queue(new_frame, None, TlbShootdownActions::NEW_MAPPING);

                        new_frame
                    }
                }
            };

            let src_frame = {
                let src_page_info = get_page_info(src_frame)
                    .expect("allocated page was not present in the global page array");

                match src_page_info.add_ref(rk) {
                    Ok(()) => src_frame,
                    Err(AddRefError::CowToShared) => {
                        let CowResult {
                            new_frame,
                            old_frame,
                        } = cow(src_frame, src_page_info, rk).map_err(|_| Enomem)?;
                        if let Some(old_frame) = old_frame {
                            src_flusher.queue(old_frame, None, TlbShootdownActions::FREE);
                        }

                        // TODO: Flusher
                        unsafe {
                            if let Some((_flags, phys, flush)) = src_mapper
                                .remap_with_full(src_page.start_address(), |_, f| {
                                    (new_frame.base(), f)
                                })
                            {
                                // TODO: flush.ignore() is correct, but seems to be amplifying a
                                // userspace race condition
                                //
                                //flush.ignore();
                                flush.flush();

                                // FIXME: Is MOVE correct?
                                src_flusher.queue(
                                    Frame::containing(phys),
                                    None,
                                    TlbShootdownActions::MOVE,
                                );
                            }
                        }

                        new_frame
                    }
                    // Cannot be shared and CoW simultaneously.
                    Err(AddRefError::SharedToCow) => {
                        // The call to cow() later implicitly removes one ref, so add it here
                        // first, even if Shared.
                        if src_page_info.add_ref(RefKind::Shared) == Err(AddRefError::RcOverflow) {
                            return Err(Enomem);
                        }

                        // TODO: Copy in place, or use a zeroed page?
                        let CowResult {
                            new_frame,
                            old_frame,
                        } = cow(src_frame, src_page_info, rk).map_err(|_| Enomem)?;
                        if let Some(old_frame) = old_frame {
                            src_flusher.queue(old_frame, None, TlbShootdownActions::FREE);
                        }
                        new_frame
                    }
                    Err(AddRefError::RcOverflow) => return Err(Enomem),
                }
            };

            let Some(map_result) = (unsafe {
                dst_mapper.map_phys(
                    dst_page,
                    src_frame.base(),
                    flags.write(flags.has_write() && allows_writable),
                )
            }) else {
                break;
            };
            unsafe {
                map_result.ignore();
            }

            dst_flusher.queue(src_frame, None, TlbShootdownActions::NEW_MAPPING);
        }

        Ok(Grant {
            base: dst_base,
            info: GrantInfo {
                page_count,
                flags,
                mapped: true,
                provider: match mode {
                    CopyMappingsMode::Owned { cow_file_ref } => Provider::Allocated {
                        cow_file_ref,
                        phys_contiguous: false,
                    },
                    CopyMappingsMode::Borrowed => Provider::AllocatedShared {
                        is_pinned_userscheme_borrow: false,
                    },
                },
            },
        })
    }
    /// Move a grant between two address spaces.
    pub fn transfer(
        mut self,
        dst_base: Page,
        flags: PageFlags<RmmA>,
        src_mapper: &mut PageMapper,
        mut dst_mapper: Option<&mut PageMapper>,
        src_flusher: &mut Flusher,
        dst_flusher: &mut impl GenericFlusher,
    ) -> Result<Grant> {
        assert!(!self.info.is_pinned());

        for src_page in self.span().pages() {
            let dst_page = dst_base.next_by(src_page.offset_from(self.base));

            let unmap_parents = true;

            // TODO: Validate flags?
            let Some((phys, _flags, flush)) =
                (unsafe { src_mapper.unmap_phys(src_page.start_address(), unmap_parents) })
            else {
                continue;
            };
            unsafe {
                flush.ignore();
            }
            src_flusher.queue(Frame::containing(phys), None, TlbShootdownActions::MOVE);

            let dst_mapper = dst_mapper.as_deref_mut().unwrap_or(&mut *src_mapper);

            // TODO: Preallocate to handle OOM?
            let flush = unsafe {
                dst_mapper
                    .map_phys(dst_page.start_address(), phys, flags)
                    .expect("TODO: OOM")
            };
            unsafe {
                flush.ignore();
            }
            dst_flusher.queue(
                Frame::containing(phys),
                None,
                TlbShootdownActions::NEW_MAPPING,
            );
        }

        self.base = dst_base;
        Ok(self)
    }

    // Caller must check this doesn't violate access rights for e.g. shared memory.
    pub fn remap(
        &mut self,
        mapper: &mut PageMapper,
        flusher: &mut Flusher,
        flags: PageFlags<RmmA>,
    ) {
        assert!(self.info.mapped);

        for page in self.span().pages() {
            unsafe {
                // Lazy mappings don't require remapping, as info.flags will be updated.
                let Some((old_flags, phys, flush)) =
                    mapper.remap_with(page.start_address(), |_| flags)
                else {
                    continue;
                };
                flush.ignore();
                //log::info!("Remapped page {:?} (frame {:?})", page, Frame::containing(mapper.translate(page.start_address()).unwrap().0));
                flusher.queue(
                    Frame::containing(phys),
                    None,
                    TlbShootdownActions::change_of_flags(old_flags, flags),
                );
            }
        }

        self.info.flags = flags;
    }
    #[must_use = "will not unmap itself"]
    pub fn unmap(
        mut self,
        mapper: &mut PageMapper,
        flusher: &mut impl GenericFlusher,
    ) -> UnmapResult {
        assert!(self.info.mapped);
        assert!(!self.info.is_pinned());

        if let Provider::External {
            ref address_space,
            src_base,
            ..
        } = self.info.provider
        {
            let mut guard = address_space.acquire_write();

            for (_, grant) in guard
                .grants
                .conflicts_mut(PageSpan::new(src_base, self.info.page_count))
            {
                match grant.provider {
                    Provider::FmapBorrowed {
                        ref mut pin_refcount,
                        ..
                    } => {
                        *pin_refcount = pin_refcount
                            .checked_sub(1)
                            .expect("fmap pinning code is wrong")
                    }
                    _ => continue,
                }
            }
        }

        let is_phys_contiguous = matches!(
            self.info.provider,
            Provider::Allocated {
                phys_contiguous: true,
                ..
            }
        );

        // TODO: Add old debug assertions back, into Flusher.
        let is_fmap_shared = match self.info.provider {
            Provider::Allocated { .. } => Some(false),
            Provider::AllocatedShared { .. } => None,
            Provider::External { .. } => None,
            Provider::PhysBorrowed { .. } => None,
            Provider::FmapBorrowed { .. } => Some(true),
        };

        if is_phys_contiguous {
            let (phys_base, _) = mapper.translate(self.base.start_address()).unwrap();
            let base_frame = Frame::containing(phys_base);

            for i in 0..self.info.page_count {
                unsafe {
                    let (phys, _, flush) = mapper
                        .unmap_phys(self.base.next_by(i).start_address(), true)
                        .expect("all physborrowed grants must be fully Present in the page tables");
                    flush.ignore();

                    assert_eq!(phys, base_frame.next_by(i).base());
                }
            }

            flusher.queue(
                base_frame,
                Some(NonZeroUsize::new(self.info.page_count).unwrap()),
                TlbShootdownActions::FREE,
            );
        } else {
            for page in self.span().pages() {
                // Lazy mappings do not need to be unmapped.
                let Some((phys, _, flush)) =
                    (unsafe { mapper.unmap_phys(page.start_address(), true) })
                else {
                    continue;
                };
                unsafe {
                    flush.ignore();
                }

                flusher.queue(Frame::containing(phys), None, TlbShootdownActions::FREE);
            }
        }

        self.info.mapped = false;

        // Dummy value, won't be read.
        let provider = core::mem::replace(
            &mut self.info.provider,
            Provider::AllocatedShared {
                is_pinned_userscheme_borrow: false,
            },
        );

        let mut munmap_flags = MunmapFlags::empty();
        munmap_flags.set(
            MunmapFlags::NEEDS_SYNC,
            is_fmap_shared.unwrap_or(false) && self.info.flags.has_write(),
        );

        UnmapResult {
            size: self.info.page_count * PAGE_SIZE,
            file_desc: match provider {
                Provider::Allocated { cow_file_ref, .. } => cow_file_ref,
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
        assert!(self.info.can_extract(false));

        let (before_span, this_span, after_span) = self.span().slice(span);

        let before_grant = before_span.map(|span| Grant {
            base: span.base,
            info: GrantInfo {
                flags: self.info.flags,
                mapped: self.info.mapped,
                page_count: span.count,
                provider: match self.info.provider {
                    Provider::External {
                        ref address_space,
                        src_base,
                        ..
                    } => Provider::External {
                        address_space: Arc::clone(address_space),
                        src_base,
                        is_pinned_userscheme_borrow: false,
                    },
                    Provider::Allocated {
                        ref cow_file_ref, ..
                    } => Provider::Allocated {
                        cow_file_ref: cow_file_ref.clone(),
                        phys_contiguous: false,
                    },
                    Provider::AllocatedShared { .. } => Provider::AllocatedShared {
                        is_pinned_userscheme_borrow: false,
                    },
                    Provider::PhysBorrowed { base } => {
                        Provider::PhysBorrowed { base: base.clone() }
                    }
                    Provider::FmapBorrowed { ref file_ref, .. } => Provider::FmapBorrowed {
                        file_ref: file_ref.clone(),
                        pin_refcount: 0,
                    },
                },
            },
        });

        let middle_page_offset = before_grant.as_ref().map_or(0, |g| g.info.page_count);

        match self.info.provider {
            Provider::PhysBorrowed { ref mut base } => *base = base.next_by(middle_page_offset),
            Provider::FmapBorrowed {
                ref mut file_ref, ..
            }
            | Provider::Allocated {
                cow_file_ref: Some(ref mut file_ref),
                ..
            } => file_ref.base_offset += middle_page_offset * PAGE_SIZE,
            Provider::Allocated {
                cow_file_ref: None, ..
            }
            | Provider::AllocatedShared { .. }
            | Provider::External { .. } => (),
        }

        let after_grant = after_span.map(|span| Grant {
            base: span.base,
            info: GrantInfo {
                flags: self.info.flags,
                mapped: self.info.mapped,
                page_count: span.count,
                provider: match self.info.provider {
                    Provider::Allocated {
                        cow_file_ref: None, ..
                    } => Provider::Allocated {
                        cow_file_ref: None,
                        phys_contiguous: false,
                    },
                    Provider::AllocatedShared { .. } => Provider::AllocatedShared {
                        is_pinned_userscheme_borrow: false,
                    },
                    Provider::Allocated {
                        cow_file_ref: Some(ref file_ref),
                        ..
                    } => Provider::Allocated {
                        cow_file_ref: Some(GrantFileRef {
                            base_offset: file_ref.base_offset + this_span.count * PAGE_SIZE,
                            description: Arc::clone(&file_ref.description),
                        }),
                        phys_contiguous: false,
                    },
                    Provider::External {
                        ref address_space,
                        src_base,
                        ..
                    } => Provider::External {
                        address_space: Arc::clone(address_space),
                        src_base,
                        is_pinned_userscheme_borrow: false,
                    },

                    Provider::PhysBorrowed { base } => Provider::PhysBorrowed {
                        base: base.next_by(this_span.count),
                    },
                    Provider::FmapBorrowed { ref file_ref, .. } => Provider::FmapBorrowed {
                        file_ref: GrantFileRef {
                            base_offset: file_ref.base_offset + this_span.count * PAGE_SIZE,
                            description: Arc::clone(&file_ref.description),
                        },
                        pin_refcount: 0,
                    },
                },
            },
        });

        self.base = this_span.base;
        self.info.page_count = this_span.count;

        Some((before_grant, self, after_grant))
    }
}
impl GrantInfo {
    pub fn is_pinned(&self) -> bool {
        matches!(
            self.provider,
            Provider::External {
                is_pinned_userscheme_borrow: true,
                ..
            } | Provider::AllocatedShared {
                is_pinned_userscheme_borrow: true,
                ..
            } | Provider::FmapBorrowed {
                pin_refcount: 1..,
                ..
            }
        )
    }
    pub fn can_extract(&self, unpin: bool) -> bool {
        !(self.is_pinned() && !unpin)
            | matches!(
                self.provider,
                Provider::Allocated {
                    phys_contiguous: true,
                    ..
                }
            )
    }
    pub fn unpin(&mut self) {
        if let Provider::External {
            ref mut is_pinned_userscheme_borrow,
            ..
        }
        | Provider::AllocatedShared {
            ref mut is_pinned_userscheme_borrow,
            ..
        } = self.provider
        {
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
        // TODO: read (some architectures support execute-only pages)
        let is_downgrade = (self.flags.has_write() || !flags.contains(MapFlags::PROT_WRITE))
            && (self.flags.has_execute() || !flags.contains(MapFlags::PROT_EXEC));

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
            (
                Provider::Allocated {
                    cow_file_ref: None,
                    phys_contiguous: false,
                },
                Provider::Allocated {
                    cow_file_ref: None,
                    phys_contiguous: false,
                },
            ) => true,
            //(Provider::PhysBorrowed { base: ref lhs }, Provider::PhysBorrowed { base: ref rhs }) => lhs.next_by(self.page_count) == rhs.clone(),
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
            Provider::External {
                is_pinned_userscheme_borrow,
                ..
            } => {
                flags.set(GrantFlags::GRANT_PINNED, is_pinned_userscheme_borrow);
                flags |= GrantFlags::GRANT_SHARED;
            }
            Provider::Allocated {
                ref cow_file_ref,
                phys_contiguous,
            } => {
                // !GRANT_SHARED is equivalent to "GRANT_PRIVATE"
                flags.set(GrantFlags::GRANT_SCHEME, cow_file_ref.is_some());
                flags.set(GrantFlags::GRANT_PHYS_CONTIGUOUS, phys_contiguous);
            }
            Provider::AllocatedShared {
                is_pinned_userscheme_borrow,
            } => {
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
        if let Provider::FmapBorrowed { ref file_ref, .. }
        | Provider::Allocated {
            cow_file_ref: Some(ref file_ref),
            ..
        } = self.provider
        {
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
        assert!(
            !self.mapped,
            "Grant dropped while still mapped: {:#x?}",
            self
        );
    }
}

pub const DANGLING: usize = 1 << (usize::BITS - 2);

#[derive(Debug)]
pub struct Table {
    pub utable: PageMapper,
}

impl Drop for AddrSpace {
    fn drop(&mut self) {
        for mut grant in core::mem::take(&mut self.grants).into_iter() {
            // Unpinning the grant is allowed, because pinning only occurs in UserScheme calls to
            // prevent unmapping the mapped range twice (which would corrupt only the scheme
            // provider), but it won't be able to double free any range after this address space
            // has been dropped!
            grant.info.unpin();

            // TODO: Optimize away clearing the actual page tables? Since this address space is no
            // longer arc-rwlock wrapped, it cannot be referenced `External`ly by borrowing grants,
            // so it should suffice to iterate over PageInfos and decrement and maybe deallocate
            // the underlying pages (and send some funmaps).
            let res = grant.unmap(&mut self.table.utable, &mut NopFlusher);

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
        unsafe {
            deallocate_frame(Frame::containing(self.utable.table().phys()));
        }
    }
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

pub struct CowResult {
    /// New frame, which has been given an exclusive reference the caller can use.
    pub new_frame: Frame,

    /// Old frame. The caller must decrease its refcount if present, after it has shot down the TLB
    /// of other CPUs properly.
    pub old_frame: Option<Frame>,
}

/// Consumes an existing reference to old_frame, and then returns an exclusive frame, with refcount
/// either preinitialized to One or Shared(2) depending on initial_ref_kind. This may be the same
/// frame, or (if the refcount is modified simultaneously) a new frame whereas the old frame is
/// deallocated.
fn cow(
    old_frame: Frame,
    old_info: &PageInfo,
    initial_ref_kind: RefKind,
) -> Result<CowResult, PfError> {
    let old_refcount = old_info.refcount();
    assert!(old_refcount.is_some());

    let initial_rc = match initial_ref_kind {
        RefKind::Cow => RefCount::One,
        RefKind::Shared => RefCount::Shared(NonZeroUsize::new(2).unwrap()),
    };

    if old_refcount == Some(RefCount::One) {
        // We were lucky; the frame was already exclusively owned, so the refcount cannot be
        // modified unless we modify it. This is the special case where the old_frame returned is
        // None.

        if initial_ref_kind == RefKind::Shared {
            old_info
                .refcount
                .store(initial_rc.to_raw(), Ordering::Relaxed);
        }
        return Ok(CowResult {
            new_frame: old_frame,
            old_frame: None,
        });
    }

    let new_frame = init_frame(initial_rc)?;

    if old_frame != the_zeroed_frame().0 {
        unsafe {
            copy_frame_to_frame_directly(new_frame, old_frame);
        }
    }

    Ok(CowResult {
        new_frame,
        old_frame: Some(old_frame),
    })
}

fn map_zeroed(
    mapper: &mut PageMapper,
    page: Page,
    page_flags: PageFlags<RmmA>,
    _writable: bool,
) -> Result<Frame, PfError> {
    let new_frame = init_frame(RefCount::One)?;

    unsafe {
        mapper
            .map_phys(page.start_address(), new_frame.base(), page_flags)
            .ok_or(PfError::Oom)?
            .ignore();
    }

    Ok(new_frame)
}

pub unsafe fn copy_frame_to_frame_directly(dst: Frame, src: Frame) {
    // Optimized exact-page-size copy function?

    // TODO: For new frames, when the kernel's linear phys=>virt mappings are 4k, this is almost
    // guaranteed to cause either one (or two) TLB misses.

    let dst = unsafe { RmmA::phys_to_virt(dst.base()).data() as *mut u8 };
    let src = unsafe { RmmA::phys_to_virt(src.base()).data() as *const u8 };

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
    let (_, flush, _) = correct_inner(lock, lock.acquire_write(), faulting_page, access, 0)?;

    flush.flush();

    Ok(())
}
fn correct_inner<'l>(
    addr_space_lock: &'l Arc<AddrSpaceWrapper>,
    mut addr_space_guard: RwLockWriteGuard<'l, AddrSpace>,
    faulting_page: Page,
    access: AccessMode,
    recursion_level: u32,
) -> Result<(Frame, PageFlush<RmmA>, RwLockWriteGuard<'l, AddrSpace>), PfError> {
    let mut addr_space = &mut *addr_space_guard;
    let mut flusher = Flusher::with_cpu_set(&mut addr_space.used_by, &addr_space_lock.tlb_ack);

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
            log::debug!("Write, but grant was not PROT_WRITE.");
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

    let faulting_frame_opt = addr_space
        .table
        .utable
        .translate(faulting_page.start_address())
        .map(|(phys, _page_flags)| Frame::containing(phys));
    let faulting_pageinfo_opt = faulting_frame_opt.map(|frame| (frame, get_page_info(frame)));

    // TODO: Aligned readahead? AMD Zen3+ CPUs can smash 4 4k pages that are 16k-aligned, into a
    // single TLB entry, thus emulating 16k pages albeit with higher page table overhead. With the
    // correct madvise information, allocating 4 contiguous pages and mapping them together, might
    // be a useful future optimization.
    //
    // TODO: Readahead backwards, i.e. MAP_GROWSDOWN.

    let mut allow_writable = true;

    let frame = match grant_info.provider {
        Provider::Allocated { .. } | Provider::AllocatedShared { .. }
            if access == AccessMode::Write =>
        {
            match faulting_pageinfo_opt {
                Some((_, None)) => unreachable!("allocated page needs frame to be valid"),
                Some((frame, Some(info))) => {
                    if info.allows_writable() {
                        frame
                    } else {
                        let result = cow(frame, info, RefKind::Cow)?;
                        if let Some(old_frame) = result.old_frame {
                            flusher.queue(old_frame, None, TlbShootdownActions::FREE);
                        }
                        result.new_frame
                    }
                }
                _ => map_zeroed(
                    &mut addr_space.table.utable,
                    faulting_page,
                    grant_flags,
                    true,
                )?,
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
                    map_zeroed(
                        &mut addr_space.table.utable,
                        faulting_page,
                        grant_flags,
                        false,
                    )?
                }
            }
        }
        Provider::PhysBorrowed { base } => base.next_by(pages_from_grant_start),
        Provider::External {
            address_space: ref foreign_address_space,
            src_base,
            ..
        } => {
            let foreign_address_space = Arc::clone(foreign_address_space);

            if Arc::ptr_eq(addr_space_lock, &foreign_address_space) {
                return Err(PfError::NonfatalInternalError);
            }

            let mut guard = foreign_address_space.acquire_upgradeable_read();
            let src_page = src_base.next_by(pages_from_grant_start);

            if let Some(_) = guard.grants.contains(src_page) {
                let src_frame = if let Some((phys, _)) =
                    guard.table.utable.translate(src_page.start_address())
                {
                    Frame::containing(phys)
                } else {
                    // Grant was valid (TODO check), but we need to correct the underlying page.
                    // TODO: Access mode

                    // TODO: Reasonable maximum?
                    let new_recursion_level = recursion_level
                        .checked_add(1)
                        .filter(|new_lvl| *new_lvl < 16)
                        .ok_or(PfError::RecursionLimitExceeded)?;

                    drop(guard);
                    drop(flusher);
                    drop(addr_space_guard);

                    // FIXME: Can this result in invalid address space state?
                    let ext_addrspace = &foreign_address_space;
                    let (frame, _, _) = {
                        let g = ext_addrspace.acquire_write();
                        correct_inner(
                            ext_addrspace,
                            g,
                            src_page,
                            AccessMode::Read,
                            new_recursion_level,
                        )?
                    };

                    addr_space_guard = addr_space_lock.acquire_write();
                    addr_space = &mut *addr_space_guard;
                    flusher =
                        Flusher::with_cpu_set(&mut addr_space.used_by, &addr_space_lock.tlb_ack);
                    guard = foreign_address_space.acquire_upgradeable_read();

                    frame
                };

                let info = get_page_info(src_frame).expect("all allocated frames need a PageInfo");

                match info.add_ref(RefKind::Shared) {
                    Ok(()) => src_frame,
                    Err(AddRefError::CowToShared) => {
                        let CowResult {
                            new_frame,
                            old_frame,
                        } = cow(src_frame, info, RefKind::Shared)?;

                        if let Some(old_frame) = old_frame {
                            flusher.queue(old_frame, None, TlbShootdownActions::FREE);
                            flusher.flush();
                        }

                        let mut guard = RwLockUpgradableGuard::upgrade(guard);

                        // TODO: flusher
                        unsafe {
                            guard
                                .table
                                .utable
                                .remap_with_full(src_page.start_address(), |_, f| {
                                    (new_frame.base(), f)
                                });
                        }

                        new_frame
                    }
                    Err(AddRefError::SharedToCow) => unreachable!(),
                    Err(AddRefError::RcOverflow) => return Err(PfError::Oom),
                }
            } else {
                // Grant did not exist, but we did own a Provider::External mapping, and cannot
                // simply let the current context fail. TODO: But all borrowed memory shouldn't
                // really be lazy though? TODO: Should a grant be created?

                let mut guard = RwLockUpgradableGuard::upgrade(guard);

                // TODO: Should this be called?
                log::warn!("Mapped zero page since grant didn't exist");
                map_zeroed(
                    &mut guard.table.utable,
                    src_page,
                    grant_flags,
                    access == AccessMode::Write,
                )?
            }
        }
        // TODO: NonfatalInternalError if !MAP_LAZY and this page fault occurs.
        Provider::FmapBorrowed { ref file_ref, .. } => {
            let file_ref = file_ref.clone();
            let flags = map_flags(grant_info.flags());
            drop(flusher);
            drop(addr_space_guard);

            let (scheme_id, scheme_number) = match file_ref.description.read() {
                ref desc => (desc.scheme, desc.number),
            };
            let user_inner = scheme::schemes()
                .get(scheme_id)
                .and_then(|s| {
                    if let KernelSchemes::User(user) = s {
                        user.inner.upgrade()
                    } else {
                        None
                    }
                })
                .ok_or(PfError::Segv)?;

            let offset = file_ref.base_offset as u64 + (pages_from_grant_start * PAGE_SIZE) as u64;
            user_inner
                .request_fmap(scheme_number, offset, 1, flags)
                .unwrap();

            let context_lock = crate::context::current();
            context_lock
                .write()
                .hard_block(HardBlockedReason::AwaitingMmap { file_ref });

            super::switch();

            let frame = context_lock
                .write()
                .fmap_ret
                .take()
                .ok_or(PfError::NonfatalInternalError)?;

            addr_space_guard = addr_space_lock.acquire_write();
            addr_space = &mut *addr_space_guard;
            flusher = Flusher::with_cpu_set(&mut addr_space.used_by, &addr_space_lock.tlb_ack);

            log::info!("Got frame {:?} from external fmap", frame);

            frame
        }
    };

    let new_flags = grant_flags.write(grant_flags.has_write() && allow_writable);
    let Some(flush) = (unsafe {
        addr_space
            .table
            .utable
            .map_phys(faulting_page.start_address(), frame.base(), new_flags)
    }) else {
        // TODO
        return Err(PfError::Oom);
    };

    drop(flusher);
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
    pub addr_space_lock: &'a Arc<AddrSpaceWrapper>,
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

// TODO: Check if polymorphism is worth it in terms of code size performance penalty vs optimized
// away checks.
pub trait GenericFlusher {
    // TODO: Don't require a frame unless FREE, require Page otherwise
    fn queue(
        &mut self,
        frame: Frame,
        phys_contiguous_count: Option<NonZeroUsize>,
        actions: TlbShootdownActions,
    );
}
pub struct NopFlusher;
impl GenericFlusher for NopFlusher {
    fn queue(
        &mut self,
        frame: Frame,
        phys_contiguous_count: Option<NonZeroUsize>,
        actions: TlbShootdownActions,
    ) {
        if actions.contains(TlbShootdownActions::FREE) {
            handle_free_action(frame, phys_contiguous_count);
        }
    }
}
fn handle_free_action(base: Frame, phys_contiguous_count: Option<NonZeroUsize>) {
    if let Some(count) = phys_contiguous_count {
        for i in 0..count.get() {
            let new_rc = get_page_info(base.next_by(i))
                .expect("phys_contiguous frames all need PageInfos")
                .remove_ref();

            assert_eq!(new_rc, None);
        }
        unsafe {
            let order = count.get().next_power_of_two().trailing_zeros();
            deallocate_p2frame(base, order);
        }
    } else {
        let Some(info) = get_page_info(base) else {
            return;
        };
        if info.remove_ref() == None {
            unsafe {
                deallocate_frame(base);
            }
        }
    }
}
struct FlusherState<'addrsp> {
    // TODO: what capacity?
    pagequeue: ArrayVec<PageQueueEntry, 32>,
    dirty: bool,

    ackword: &'addrsp AtomicU32,
}

enum PageQueueEntry {
    Free {
        base: Frame,
        phys_contiguous_count: Option<NonZeroUsize>,
    },
    Other {
        actions: TlbShootdownActions,
        //page: Page,
    },
}

pub struct Flusher<'guard, 'addrsp> {
    active_cpus: &'guard mut LogicalCpuSet,
    state: FlusherState<'addrsp>,
}
impl<'guard, 'addrsp> Flusher<'guard, 'addrsp> {
    fn with_cpu_set(set: &'guard mut LogicalCpuSet, ackword: &'addrsp AtomicU32) -> Self {
        Self {
            active_cpus: set,
            state: FlusherState {
                pagequeue: ArrayVec::new(),
                dirty: false,
                ackword,
            },
        }
    }
    fn detach(mut self) -> FlusherState<'addrsp> {
        static DUMMY: AtomicU32 = AtomicU32::new(0);
        let state = core::mem::replace(
            &mut self.state,
            FlusherState {
                pagequeue: ArrayVec::new(),
                ackword: &DUMMY,
                dirty: false,
            },
        );
        core::mem::forget(self);
        state
    }
    // NOTE: Lock must be held, which must be guaranteed by the caller.
    pub fn flush(&mut self) {
        let pages = core::mem::take(&mut self.state.pagequeue);

        if pages.is_empty() && core::mem::replace(&mut self.state.dirty, false) == false {
            return;
        }

        self.state.ackword.store(0, Ordering::SeqCst);

        let mut affected_cpu_count = 0;

        let current_cpu_id = crate::cpu_id();

        for cpu_id in self.active_cpus.iter_mut() {
            if cpu_id == current_cpu_id {
                continue;
            }

            crate::percpu::shootdown_tlb_ipi(Some(cpu_id));
            affected_cpu_count += 1;
        }

        if self.active_cpus.contains(current_cpu_id) {
            rmm::PageFlushAll::<RmmA>::new().flush();
        }

        while self.state.ackword.load(Ordering::SeqCst) < affected_cpu_count {
            PercpuBlock::current().maybe_handle_tlb_shootdown();
            core::hint::spin_loop();
        }

        for entry in pages {
            let PageQueueEntry::Free {
                base,
                phys_contiguous_count,
            } = entry
            else {
                continue;
            };
            handle_free_action(base, phys_contiguous_count);
        }
    }
}
impl GenericFlusher for Flusher<'_, '_> {
    fn queue(
        &mut self,
        frame: Frame,
        phys_contiguous_count: Option<NonZeroUsize>,
        actions: TlbShootdownActions,
    ) {
        let actions = actions & !TlbShootdownActions::NEW_MAPPING;

        let entry = if actions.contains(TlbShootdownActions::FREE) {
            PageQueueEntry::Free {
                base: frame,
                phys_contiguous_count,
            }
        } else {
            PageQueueEntry::Other { actions }
        };
        self.state.dirty = true;

        if self.state.pagequeue.is_full() {
            self.flush();
        }
        self.state.pagequeue.push(entry);
    }
}
impl Drop for Flusher<'_, '_> {
    fn drop(&mut self) {
        self.flush();
    }
}
bitflags::bitflags! {
    pub struct TlbShootdownActions: usize {
        // Delay the deallocation of one or more contiguous frames.
        const FREE = 1;

        // Revoke various access flags from a page
        const REVOKE_READ = 1 << 1;
        const REVOKE_WRITE = 1 << 2;
        const REVOKE_EXEC = 1 << 3;

        // Unmap a page from one address space without deallocating it.
        const MOVE = 1 << 4;

        // Add a new mapping to an address space.
        // Not really a TLB shootdown action on most architectures, so almost always a no-op.
        const NEW_MAPPING = 1 << 31;
    }
}
impl TlbShootdownActions {
    pub fn change_of_flags(old: PageFlags<RmmA>, new: PageFlags<RmmA>) -> Self {
        let mut this = Self::empty();
        this.set(Self::REVOKE_WRITE, old.has_write() && !new.has_write());
        this.set(Self::REVOKE_EXEC, old.has_execute() && !new.has_execute());
        this
    }
}
