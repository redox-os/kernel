use crate::interrupt::InterruptStack;
use crate::memory::{allocate_frames_complex, deallocate_frames, Frame};
use crate::paging::{ActivePageTable, PageFlags, PhysicalAddress, VirtualAddress};
use crate::paging::entry::EntryFlags;
use crate::context;
use crate::context::memory::{Grant, Region};
use crate::syscall::error::{Error, EFAULT, EINVAL, ENOMEM, EPERM, ESRCH, Result};
use crate::syscall::flag::{PhysallocFlags, PartialAllocStrategy, PhysmapFlags, PHYSMAP_WRITE, PHYSMAP_WRITE_COMBINE, PHYSMAP_NO_CACHE};

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
pub fn inner_physmap(physical_address: usize, size: usize, flags: PhysmapFlags) -> Result<usize> {
    //TODO: Abstract with other grant creation
    if size == 0 {
        Ok(0)
    } else {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        let mut grants = context.grants.write();

        let from_address = (physical_address/4096) * 4096;
        let offset = physical_address - from_address;
        let full_size = ((offset + size + 4095)/4096) * 4096;
        let mut to_address = crate::USER_GRANT_OFFSET;

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

        // TODO: Make this faster than Sonic himself by using le superpowers of BTreeSet

        for grant in grants.iter() {
            let start = grant.start_address().data();
            if to_address + full_size < start {
                break;
            }

            let pages = (grant.size() + 4095) / 4096;
            let end = start + pages * 4096;
            to_address = end;
        }

        grants.insert(Grant::physmap(
            PhysicalAddress::new(from_address),
            VirtualAddress::new(to_address),
            full_size,
            page_flags
        ));

        Ok(to_address + offset)
    }
}
pub fn physmap(physical_address: usize, size: usize, flags: PhysmapFlags) -> Result<usize> {
    enforce_root()?;
    inner_physmap(physical_address, size, flags)
}

pub fn inner_physunmap(virtual_address: usize) -> Result<usize> {
    if virtual_address == 0 {
        Ok(0)
    } else {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        let mut grants = context.grants.write();

        if let Some(region) = grants.contains(VirtualAddress::new(virtual_address)).map(Region::from) {
            grants.take(&region).unwrap().unmap();
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

    let active_table = unsafe { ActivePageTable::new(VirtualAddress::new(virtual_address).kind()) };

    match active_table.translate(VirtualAddress::new(virtual_address)) {
        Some(physical_address) => Ok(physical_address.data()),
        None => Err(Error::new(EFAULT))
    }
}
