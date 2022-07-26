use crate::interrupt::InterruptStack;
use crate::memory::{allocate_frames_complex, deallocate_frames, Frame, PAGE_SIZE};
use crate::paging::{Page, PageFlags, PhysicalAddress, VirtualAddress, mapper::PageFlushAll};
use crate::paging::entry::EntryFlags;
use crate::context;
use crate::context::memory::{DANGLING, Grant, Region};
use crate::syscall::error::{Error, EFAULT, EINVAL, ENOMEM, EPERM, ESRCH, Result};
use crate::syscall::flag::{PhysallocFlags, PartialAllocStrategy, PhysmapFlags, PHYSMAP_WRITE, PHYSMAP_WRITE_COMBINE, PHYSMAP_NO_CACHE};

use alloc::sync::Arc;

fn enforce_root() -> Result<()> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    if context.euid == 0 {
        Ok(())
    } else {
        Err(Error::new(EPERM))
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn iopl(level: usize, stack: &mut InterruptStack) -> Result<usize> {
    Err(Error::new(syscall::error::ENOSYS))
}

#[cfg(target_arch = "x86_64")]
pub fn iopl(level: usize, stack: &mut InterruptStack) -> Result<usize> {
    enforce_root()?;

    if level > 3 {
        return Err(Error::new(EINVAL));
    }

    stack.iret.rflags = (stack.iret.rflags & !(3 << 12)) | ((level & 3) << 12);

    Ok(0)
}

pub fn inner_physalloc(size: usize, flags: PhysallocFlags, strategy: Option<PartialAllocStrategy>, min: usize) -> Result<(usize, usize)> {
    if flags.contains(PhysallocFlags::SPACE_32 | PhysallocFlags::SPACE_64) {
        return Err(Error::new(EINVAL));
    }
    allocate_frames_complex((size + 4095) / 4096, flags, strategy, (min + 4095) / 4096).ok_or(Error::new(ENOMEM)).map(|(frame, count)| (frame.start_address().data(), count * 4096))
}
pub fn physalloc(size: usize) -> Result<usize> {
    enforce_root()?;
    inner_physalloc(size, PhysallocFlags::SPACE_64, None, size).map(|(base, _)| base)
}
pub fn physalloc3(size: usize, flags_raw: usize, min: &mut usize) -> Result<usize> {
    enforce_root()?;
    let flags = PhysallocFlags::from_bits(flags_raw & !syscall::PARTIAL_ALLOC_STRATEGY_MASK).ok_or(Error::new(EINVAL))?;
    let strategy = if flags.contains(PhysallocFlags::PARTIAL_ALLOC) {
        Some(PartialAllocStrategy::from_raw(flags_raw & syscall::PARTIAL_ALLOC_STRATEGY_MASK).ok_or(Error::new(EINVAL))?)
    } else {
        None
    };
    let (base, count) = inner_physalloc(size, flags, strategy, *min)?;
    *min = count;
    Ok(base)
}

pub fn inner_physfree(physical_address: usize, size: usize) -> Result<usize> {
    deallocate_frames(Frame::containing_address(PhysicalAddress::new(physical_address)), (size + 4095)/4096);

    //TODO: Check that no double free occured
    Ok(0)
}
pub fn physfree(physical_address: usize, size: usize) -> Result<usize> {
    enforce_root()?;
    inner_physfree(physical_address, size)
}

//TODO: verify exlusive access to physical memory
// TODO: Replace this completely with something such as `memory:physical`. Mmapping at offset
// `physaddr` to `address` (optional) will map that physical address. We would have to find out
// some way to pass flags such as WRITE_COMBINE/NO_CACHE however.
pub fn inner_physmap(physical_address: usize, size: usize, flags: PhysmapFlags) -> Result<usize> {
    // TODO: Check physical_address against MAXPHYADDR.

    let end = 1 << 52;
    if physical_address.saturating_add(size) > end || physical_address % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
        return Err(Error::new(EINVAL));
    }

    let addr_space = Arc::clone(context::current()?.read().addr_space()?);
    let mut addr_space = addr_space.write();

    addr_space.mmap(None, size / PAGE_SIZE, Default::default(), |dst_page, _, dst_mapper, dst_flusher| {
        let mut page_flags = PageFlags::new().user(true);
        if flags.contains(PHYSMAP_WRITE) {
            page_flags = page_flags.write(true);
        }
        if flags.contains(PHYSMAP_WRITE_COMBINE) {
            page_flags = page_flags.custom_flag(EntryFlags::HUGE_PAGE.bits(), true);
        }
        #[cfg(target_arch = "x86_64")] // TODO: AARCH64
        if flags.contains(PHYSMAP_NO_CACHE) {
            page_flags = page_flags.custom_flag(EntryFlags::NO_CACHE.bits(), true);
        }
        Grant::physmap(
            Frame::containing_address(PhysicalAddress::new(physical_address)),
            dst_page,
            size / PAGE_SIZE,
            page_flags,
            dst_mapper,
            dst_flusher,
        )
    }).map(|page| page.start_address().data())

}
// TODO: Remove this syscall, funmap makes it redundant.
pub fn physmap(physical_address: usize, size: usize, flags: PhysmapFlags) -> Result<usize> {
    enforce_root()?;
    inner_physmap(physical_address, size, flags)
}

pub fn inner_physunmap(virtual_address: usize) -> Result<usize> {
    if virtual_address == 0 {
        Ok(0)
    } else {
        let addr_space = Arc::clone(context::current()?.read().addr_space()?);
        let mut addr_space = addr_space.write();

        if let Some(region) = addr_space.grants.contains(VirtualAddress::new(virtual_address)).map(Region::from) {

            addr_space.grants.take(&region).unwrap().unmap(&mut addr_space.table.utable, PageFlushAll::new());
            return Ok(0);
        }

        Err(Error::new(EFAULT))
    }
}
pub fn physunmap(virtual_address: usize) -> Result<usize> {
    enforce_root()?;
    inner_physunmap(virtual_address)
}

pub fn virttophys(virtual_address: usize) -> Result<usize> {
    enforce_root()?;

    let addr_space = Arc::clone(context::current()?.read().addr_space()?);
    let addr_space = addr_space.read();

    match addr_space.table.utable.translate(VirtualAddress::new(virtual_address)) {
        Some((physical_address, _)) => Ok(physical_address.data()),
        None => Err(Error::new(EFAULT))
    }
}
