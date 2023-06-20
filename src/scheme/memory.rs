use core::num::NonZeroUsize;

use alloc::sync::Arc;
use rmm::PhysicalAddress;
use spin::RwLock;
use syscall::MapFlags;

use crate::context::memory::{AddrSpace, Grant, PageSpan};
use crate::memory::{free_frames, used_frames, PAGE_SIZE, Frame};
use crate::paging::VirtualAddress;

use crate::paging::entry::EntryFlags;
use crate::syscall::data::{Map, StatVfs};
use crate::syscall::error::*;
use crate::syscall::scheme::Scheme;
use crate::syscall::usercopy::UserSliceWo;

use super::KernelScheme;

pub struct MemoryScheme;

// TODO: Use crate that autogenerates conversion functions.
#[repr(u8)]
enum Handle {
    Anonymous = 0,

    PhysicalWb = 1,
    PhysicalUc = 2,
    PhysicalWc = 3,

    // TODO: More/make arch-specific?
}
pub enum MemoryType {
    Writeback,
    Uncacheable,
    WriteCombining,
}

impl Handle {
    fn from_raw(raw: usize) -> Option<Self> {
        Some(match raw {
            0 => Self::Anonymous,

            1 => Self::PhysicalWb,
            2 => Self::PhysicalUc,
            3 => Self::PhysicalWc,

            _ => return None,
        })
    }
}

impl MemoryScheme {
    pub fn new() -> Self {
        MemoryScheme
    }

    pub fn fmap_anonymous(addr_space: &Arc<RwLock<AddrSpace>>, map: &Map) -> Result<usize> {
        let span = PageSpan::validate_nonempty(VirtualAddress::new(map.address), map.size).ok_or(Error::new(EINVAL))?;
        let page_count = NonZeroUsize::new(span.count).ok_or(Error::new(EINVAL))?;

        let page = addr_space
            .write()
            .mmap((map.address != 0).then_some(span.base), page_count, map.flags, |page, flags, mapper, flusher| {
                Ok(Grant::zeroed(page, page_count.get(), flags, mapper, flusher)?)
            })?;

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

        AddrSpace::current()?.write().mmap(None, page_count, flags, |dst_page, mut page_flags, dst_mapper, dst_flusher| {
            match memory_type {
                // Default
                MemoryType::Writeback => (),

                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] // TODO: AARCH64
                MemoryType::WriteCombining => page_flags = page_flags.custom_flag(EntryFlags::HUGE_PAGE.bits(), true),

                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] // TODO: AARCH64
                MemoryType::Uncacheable => page_flags = page_flags.custom_flag(EntryFlags::NO_CACHE.bits(), true),

                #[cfg(target_arch = "aarch64")]
                _ => (),
            }

            Grant::physmap(
                Frame::containing_address(PhysicalAddress::new(physical_address)),
                dst_page,
                page_count.get(),
                page_flags,
                dst_mapper,
                dst_flusher,
            )
        }).map(|page| page.start_address().data())

    }
}
impl Scheme for MemoryScheme {
    fn open(&self, path: &str, _flags: usize, uid: u32, _gid: u32) -> Result<usize> {
        let intended_handle = match path.trim_start_matches('/') {
            "" => Handle::Anonymous,
            "physical" | "physical@wb" => Handle::PhysicalWb,
            "physical@uc" => Handle::PhysicalUc,
            "physical@wc" => Handle::PhysicalWc,

            _ => return Err(Error::new(ENOENT)),
        };

        if uid != 0 && !matches!(intended_handle, Handle::Anonymous) {
            return Err(Error::new(EACCES));
        }

        Ok(intended_handle as usize)
    }

    fn fmap(&self, id: usize, map: &Map) -> Result<usize> {
        self.kfmap(id, &AddrSpace::current()?, map, false)
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn close(&self, _id: usize) -> Result<usize> {
        Ok(0)
    }
}
impl KernelScheme for MemoryScheme {
    fn kfmap(&self, id: usize, addr_space: &Arc<RwLock<AddrSpace>>, map: &Map, _consume: bool) -> Result<usize> {
        match Handle::from_raw(id).ok_or(Error::new(EBADF))? {
            Handle::Anonymous => Self::fmap_anonymous(addr_space, map),
            Handle::PhysicalWb => Self::physmap(map.offset, map.size, map.flags, MemoryType::Writeback),
            Handle::PhysicalUc => Self::physmap(map.offset, map.size, map.flags, MemoryType::Uncacheable),
            Handle::PhysicalWc => Self::physmap(map.offset, map.size, map.flags, MemoryType::WriteCombining),
        }
    }
    fn kfpath(&self, id: usize, dst: UserSliceWo) -> Result<usize> {
        // TODO: Copy scheme name elsewhere in the kernel?
        let src = match Handle::from_raw(id).ok_or(Error::new(EBADF))? {
            Handle::Anonymous => "memory:",
            Handle::PhysicalWb => "memory:physical@wb",
            Handle::PhysicalUc => "memory:physical@uc",
            Handle::PhysicalWc => "memory:physical@wc",
        };
        dst.copy_common_bytes_from_slice(src.as_bytes())
    }
    fn kfstatvfs(&self, _file: usize, dst: UserSliceWo) -> Result<usize> {
        let used = used_frames() as u64;
        let free = free_frames() as u64;

        let stat = StatVfs {
            f_bsize: PAGE_SIZE.try_into().map_err(|_| Error::new(EOVERFLOW))?,
            f_blocks: used + free,
            f_bfree: free,
            f_bavail: free,
        };
        dst.copy_exactly(&stat)?;

        Ok(0)
    }
}
