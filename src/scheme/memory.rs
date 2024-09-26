use core::num::NonZeroUsize;

use alloc::{sync::Arc, vec::Vec};
use rmm::PhysicalAddress;

use crate::{
    context::{
        file::InternalFlags,
        memory::{handle_notify_files, AddrSpace, AddrSpaceWrapper, Grant, PageSpan},
    },
    memory::{free_frames, used_frames, Frame, PAGE_SIZE},
    paging::VirtualAddress,
};

use crate::paging::entry::EntryFlags;

use crate::syscall::{
    data::{Map, StatVfs},
    error::*,
    flag::MapFlags,
    usercopy::UserSliceWo,
};

use super::{CallerCtx, KernelScheme, OpenResult};

pub struct MemoryScheme;

// TODO: Use crate that autogenerates conversion functions.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum HandleTy {
    Allocated = 0,
    PhysBorrow = 1,
}
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MemoryType {
    Writeback = 0,
    Uncacheable = 1,
    WriteCombining = 2,
    DeviceMemory = 3,
}

bitflags! {
    struct HandleFlags: u16 {
        // TODO: below 32 bits?
        const PHYS_CONTIGUOUS = 1;
    }
}

fn from_raw(raw: u32) -> Option<(HandleTy, MemoryType, HandleFlags)> {
    Some((
        match raw & 0xFF {
            0 => HandleTy::Allocated,
            1 => HandleTy::PhysBorrow,

            _ => return None,
        },
        match (raw >> 8) & 0xFF {
            0 => MemoryType::Writeback,
            1 => MemoryType::Uncacheable,
            2 => MemoryType::WriteCombining,
            3 => MemoryType::DeviceMemory,

            _ => return None,
        },
        HandleFlags::from_bits_truncate((raw >> 16) as u16),
    ))
}

impl MemoryScheme {
    pub fn fmap_anonymous(
        addr_space: &Arc<AddrSpaceWrapper>,
        map: &Map,
        is_phys_contiguous: bool,
    ) -> Result<usize> {
        let span = PageSpan::validate_nonempty(VirtualAddress::new(map.address), map.size)
            .ok_or(Error::new(EINVAL))?;
        let page_count = NonZeroUsize::new(span.count).ok_or(Error::new(EINVAL))?;

        let mut notify_files = Vec::new();

        if is_phys_contiguous && map.flags.contains(MapFlags::MAP_SHARED) {
            // TODO: Should this be supported?
            return Err(Error::new(EOPNOTSUPP));
        }

        let page = addr_space.acquire_write().mmap(
            &addr_space,
            (map.address != 0).then_some(span.base),
            page_count,
            map.flags,
            &mut notify_files,
            |dst_page, flags, mapper, flusher| {
                let span = PageSpan::new(dst_page, page_count.get());
                if is_phys_contiguous {
                    Ok(Grant::zeroed_phys_contiguous(span, flags, mapper, flusher)?)
                } else {
                    Ok(Grant::zeroed(
                        span,
                        flags,
                        mapper,
                        flusher,
                        map.flags.contains(MapFlags::MAP_SHARED),
                    )?)
                }
            },
        )?;

        handle_notify_files(notify_files);

        Ok(page.start_address().data())
    }
    pub fn physmap(
        physical_address: usize,
        size: usize,
        flags: MapFlags,
        memory_type: MemoryType,
    ) -> Result<usize> {
        // TODO: Check physical_address against the real MAXPHYADDR.
        let end = 1 << 52;
        if (physical_address.saturating_add(size) as u64) > end || physical_address % PAGE_SIZE != 0
        {
            return Err(Error::new(EINVAL));
        }

        if size % PAGE_SIZE != 0 {
            log::warn!(
                "physmap size {} is not multiple of PAGE_SIZE {}",
                size,
                PAGE_SIZE
            );
            return Err(Error::new(EINVAL));
        }
        let page_count = NonZeroUsize::new(size.div_ceil(PAGE_SIZE)).ok_or(Error::new(EINVAL))?;

        let current_addrsp = AddrSpace::current()?;

        let base_page = current_addrsp.acquire_write().mmap_anywhere(
            &current_addrsp,
            page_count,
            flags,
            |dst_page, mut page_flags, dst_mapper, dst_flusher| {
                match memory_type {
                    // Default
                    MemoryType::Writeback => (),

                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] // TODO: AARCH64
                    MemoryType::WriteCombining => {
                        page_flags = page_flags.custom_flag(EntryFlags::HUGE_PAGE.bits(), true)
                    }

                    MemoryType::Uncacheable => {
                        page_flags = page_flags.custom_flag(EntryFlags::NO_CACHE.bits(), true)
                    }

                    // MemoryType::DeviceMemory doesn't exist on x86 && x86_64, which instead support
                    // uncacheable, write-combining, write-through, write-protect, and write-back.
                    #[cfg(target_arch = "aarch64")]
                    MemoryType::DeviceMemory => {
                        page_flags = page_flags.custom_flag(EntryFlags::DEV_MEM.bits(), true)
                    }

                    _ => (),
                }

                Grant::physmap(
                    Frame::containing(PhysicalAddress::new(physical_address)),
                    PageSpan::new(dst_page, page_count.get()),
                    page_flags,
                    dst_mapper,
                    dst_flusher,
                )
            },
        )?;
        Ok(base_page.start_address().data())
    }
}
impl KernelScheme for MemoryScheme {
    fn kopen(&self, path: &str, _flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        if path.len() > 64 {
            return Err(Error::new(ENOENT));
        }
        let path = path.trim_start_matches('/');

        let (before_memty, memty_str) = path.split_once('@').unwrap_or((path, ""));
        let (before_ty, type_str) = memty_str.split_once('?').unwrap_or((memty_str, ""));

        let handle_ty = match before_memty {
            "" | "zeroed" => HandleTy::Allocated,
            "physical" => HandleTy::PhysBorrow,

            _ => return Err(Error::new(ENOENT)),
        };
        let mem_ty = match before_ty {
            "" | "wb" => MemoryType::Writeback,
            "wc" => MemoryType::WriteCombining,
            "uc" => MemoryType::Uncacheable,
            "dev" => MemoryType::DeviceMemory,

            _ => return Err(Error::new(ENOENT)),
        };

        let flags = type_str
            .split(',')
            .filter_map(|ty_str| match ty_str {
                //"32" => HandleFlags::BELOW_4G,
                "phys_contiguous" => Some(Some(HandleFlags::PHYS_CONTIGUOUS)),
                "" => None,
                _ => Some(None),
            })
            .collect::<Option<HandleFlags>>()
            .ok_or(Error::new(ENOENT))?;

        // TODO: Support arches with other default memory types?
        if ctx.uid != 0
            && (!flags.is_empty()
                || !matches!(
                    (handle_ty, mem_ty),
                    (HandleTy::Allocated, MemoryType::Writeback)
                ))
        {
            return Err(Error::new(EACCES));
        }

        Ok(OpenResult::SchemeLocal(
            (handle_ty as usize) | ((mem_ty as usize) << 8) | (usize::from(flags.bits()) << 16),
            InternalFlags::empty(),
        ))
    }

    fn kfmap(
        &self,
        id: usize,
        addr_space: &Arc<AddrSpaceWrapper>,
        map: &Map,
        _consume: bool,
    ) -> Result<usize> {
        let (handle_ty, mem_ty, flags) = u32::try_from(id)
            .ok()
            .and_then(from_raw)
            .ok_or(Error::new(EBADF))?;

        match handle_ty {
            HandleTy::Allocated => Self::fmap_anonymous(
                addr_space,
                map,
                flags.contains(HandleFlags::PHYS_CONTIGUOUS),
            ),
            HandleTy::PhysBorrow => Self::physmap(map.offset, map.size, map.flags, mem_ty),
        }
    }
    fn kfstatvfs(&self, _file: usize, dst: UserSliceWo) -> Result<()> {
        let used = used_frames() as u64;
        let free = free_frames() as u64;

        let stat = StatVfs {
            f_bsize: PAGE_SIZE.try_into().map_err(|_| Error::new(EOVERFLOW))?,
            f_blocks: used + free,
            f_bfree: free,
            f_bavail: free,
        };
        dst.copy_exactly(&stat)?;

        Ok(())
    }
}
