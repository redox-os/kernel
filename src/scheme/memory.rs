use core::num::NonZeroUsize;

use alloc::sync::Arc;
use rmm::PhysicalAddress;
use alloc::vec::Vec;
use spin::RwLock;

use crate::memory::{free_frames, used_frames, PAGE_SIZE, Frame};
use crate::context::memory::{AddrSpace, Grant, PageSpan, handle_notify_files};
use crate::paging::VirtualAddress;

use crate::paging::entry::EntryFlags;

use crate::syscall::data::{Map, StatVfs};
use crate::syscall::flag::MapFlags;
use crate::syscall::error::*;
use crate::syscall::usercopy::UserSliceWo;

use super::{KernelScheme, CallerCtx, OpenResult};

pub struct MemoryScheme;

// TODO: Use crate that autogenerates conversion functions.
#[repr(u8)]
enum Handle {
    Zeroed = 0,
    ZeroedPhysContiguous = 4,

    PhysicalWb = 1,
    PhysicalUc = 2,
    PhysicalWc = 3,
    PhysicalDev = 4,

    // TODO: More/make arch-specific?
}
pub enum MemoryType {
    Writeback,
    Uncacheable,
    WriteCombining,
    DeviceMemory,
}

impl Handle {
    fn from_raw(raw: usize) -> Option<Self> {
        Some(match raw {
            0 => Self::Zeroed,
            4 => Self::ZeroedPhysContiguous,

            1 => Self::PhysicalWb,
            2 => Self::PhysicalUc,
            3 => Self::PhysicalWc,
            4 => Self::PhysicalDev,

            _ => return None,
        })
    }
}

impl MemoryScheme {
    pub fn fmap_anonymous(addr_space: &Arc<RwLock<AddrSpace>>, map: &Map, is_phys_contiguous: bool) -> Result<usize> {
        let span = PageSpan::validate_nonempty(VirtualAddress::new(map.address), map.size).ok_or(Error::new(EINVAL))?;
        let page_count = NonZeroUsize::new(span.count).ok_or(Error::new(EINVAL))?;

        let mut notify_files = Vec::new();

        if is_phys_contiguous && map.flags.contains(MapFlags::MAP_SHARED) {
            // TODO: Should this be supported?
            return Err(Error::new(EOPNOTSUPP));
        }

        let page = addr_space
            .write()
            .mmap((map.address != 0).then_some(span.base), page_count, map.flags, &mut notify_files, |dst_page, flags, mapper, flusher| {
                let span = PageSpan::new(dst_page, page_count.get());
                if is_phys_contiguous {
                    Ok(Grant::zeroed_phys_contiguous(span, flags, mapper, flusher)?)
                } else {
                    Ok(Grant::zeroed(span, flags, mapper, flusher, map.flags.contains(MapFlags::MAP_SHARED))?)
                }
            })?;

        handle_notify_files(notify_files);

        Ok(page.start_address().data())
    }
    pub fn physmap(physical_address: usize, size: usize, flags: MapFlags, memory_type: MemoryType) -> Result<usize> {
        // TODO: Check physical_address against the real MAXPHYADDR.
        let end = 1 << 52;
        if (physical_address.saturating_add(size) as u64) > end || physical_address % PAGE_SIZE != 0 {
            return Err(Error::new(EINVAL));
        }
        // TODO: Check that the physical address is not owned by the frame allocator, although this
        // requires replacing physalloc and physfree with e.g. MAP_PHYS_CONTIGUOUS.

        if size % PAGE_SIZE != 0 {
            log::warn!("physmap size {} is not multiple of PAGE_SIZE {}", size, PAGE_SIZE);
            return Err(Error::new(EINVAL));
        }
        let page_count = NonZeroUsize::new(size.div_ceil(PAGE_SIZE)).ok_or(Error::new(EINVAL))?;

        AddrSpace::current()?.write().mmap_anywhere(page_count, flags, |dst_page, mut page_flags, dst_mapper, dst_flusher| {
            match memory_type {
                // Default
                MemoryType::Writeback => (),

                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] // TODO: AARCH64
                MemoryType::WriteCombining => page_flags = page_flags.custom_flag(EntryFlags::HUGE_PAGE.bits(), true),

                MemoryType::Uncacheable => page_flags = page_flags.custom_flag(EntryFlags::NO_CACHE.bits(), true),

                #[cfg(target_arch = "aarch64")]
                MemoryType::DeviceMemory => page_flags = page_flags.custom_flag(EntryFlags::DEV_MEM.bits(), true),

                //x86 && x86_64 MemoryType::DeviceMemory unimplemented
                //aarch64 MemoryType::WriteCombining unimplemented
                _ => (),
            }

            Grant::physmap(
                Frame::containing_address(PhysicalAddress::new(physical_address)),
                PageSpan::new(
                    dst_page,
                    page_count.get(),
                ),
                page_flags,
                dst_mapper,
                dst_flusher,
            )
        }).map(|page| page.start_address().data())

    }
}
impl KernelScheme for MemoryScheme {
    fn kopen(&self, path: &str, _flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        let intended_handle = match path.trim_start_matches('/') {
            "" | "zeroed" => Handle::Zeroed,
            "zeroed_phys_contiguous" => Handle::ZeroedPhysContiguous,
            "physical" | "physical@wb" => Handle::PhysicalWb,
            "physical@uc" => Handle::PhysicalUc,
            "physical@wc" => Handle::PhysicalWc,
            "physical@dev" => Handle::PhysicalDev,

            _ => return Err(Error::new(ENOENT)),
        };

        if ctx.uid != 0 && !matches!(intended_handle, Handle::Zeroed) {
            return Err(Error::new(EACCES));
        }

        Ok(OpenResult::SchemeLocal(intended_handle as usize))
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn close(&self, _id: usize) -> Result<()> {
        Ok(())
    }
    fn kfmap(&self, id: usize, addr_space: &Arc<RwLock<AddrSpace>>, map: &Map, _consume: bool) -> Result<usize> {
        match Handle::from_raw(id).ok_or(Error::new(EBADF))? {
            Handle::Zeroed => Self::fmap_anonymous(addr_space, map, false),
            Handle::ZeroedPhysContiguous => Self::fmap_anonymous(addr_space, map, true),
            Handle::PhysicalWb => Self::physmap(map.offset, map.size, map.flags, MemoryType::Writeback),
            Handle::PhysicalUc => Self::physmap(map.offset, map.size, map.flags, MemoryType::Uncacheable),
            Handle::PhysicalWc => Self::physmap(map.offset, map.size, map.flags, MemoryType::WriteCombining),
            Handle::PhysicalDev => Self::physmap(map.offset, map.size, map.flags, MemoryType::DeviceMemory),
        }
    }
    fn kfpath(&self, id: usize, dst: UserSliceWo) -> Result<usize> {
        // TODO: Copy scheme name elsewhere in the kernel?
        let src = match Handle::from_raw(id).ok_or(Error::new(EBADF))? {
            Handle::Zeroed => "memory:zeroed",
            Handle::ZeroedPhysContiguous => "memory:zeroed_phys_contiguous",
            Handle::PhysicalWb => "memory:physical@wb",
            Handle::PhysicalUc => "memory:physical@uc",
            Handle::PhysicalWc => "memory:physical@wc",
            Handle::PhysicalDev => "memory:physical@dev",
        };
        dst.copy_common_bytes_from_slice(src.as_bytes())
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
