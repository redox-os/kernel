use core::num::NonZeroUsize;

use crate::interrupt::InterruptStack;
use crate::memory::{allocate_frames_complex, deallocate_frames, Frame, PAGE_SIZE};
use crate::paging::{PhysicalAddress, VirtualAddress};
use crate::context;
use crate::scheme::memory::{MemoryScheme, MemoryType};
use crate::syscall::error::{Error, EFAULT, EINVAL, ENOMEM, EPERM, ESRCH, Result};
use crate::syscall::flag::{MapFlags, PhysallocFlags, PartialAllocStrategy, PhysmapFlags};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]

use alloc::sync::Arc;

use super::usercopy::UserSliceRw;

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

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn iopl(level: usize, stack: &mut InterruptStack) -> Result<usize> {
    Err(Error::new(syscall::error::ENOSYS))
}

#[cfg(target_arch = "x86")]
pub fn iopl(level: usize, stack: &mut InterruptStack) -> Result<usize> {
    enforce_root()?;

    if level > 3 {
        return Err(Error::new(EINVAL));
    }

    stack.iret.eflags = (stack.iret.eflags & !(3 << 12)) | ((level & 3) << 12);

    Ok(0)
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

pub fn inner_physalloc(size: usize, flags: PhysallocFlags, strategy: Option<PartialAllocStrategy>, _min: usize) -> Result<(usize, usize)> {
    if flags.contains(PhysallocFlags::SPACE_32 | PhysallocFlags::SPACE_64) {
        return Err(Error::new(EINVAL));
    }
    allocate_frames_complex(size.div_ceil(PAGE_SIZE), flags, strategy, size.div_ceil(PAGE_SIZE)).ok_or(Error::new(ENOMEM)).map(|(frame, count)| (frame.start_address().data(), count * PAGE_SIZE))
}
pub fn physalloc(size: usize) -> Result<usize> {
    enforce_root()?;
    inner_physalloc(size, PhysallocFlags::SPACE_64, None, size).map(|(base, _)| base)
}
pub fn physalloc3(size: usize, flags_raw: usize, min_inout_usize: UserSliceRw) -> Result<usize> {
    enforce_root()?;
    let flags = PhysallocFlags::from_bits(flags_raw & !syscall::PARTIAL_ALLOC_STRATEGY_MASK).ok_or(Error::new(EINVAL))?;
    let strategy = if flags.contains(PhysallocFlags::PARTIAL_ALLOC) {
        Some(PartialAllocStrategy::from_raw(flags_raw & syscall::PARTIAL_ALLOC_STRATEGY_MASK).ok_or(Error::new(EINVAL))?)
    } else {
        None
    };
    let (base, count) = inner_physalloc(size, flags, strategy, min_inout_usize.read_usize()?)?;

    // TODO: handle error
    let _ = min_inout_usize.write_usize(count);

    Ok(base)
}

pub fn inner_physfree(physical_address: usize, size: usize) -> Result<usize> {
    deallocate_frames(Frame::containing_address(PhysicalAddress::new(physical_address)), size.div_ceil(PAGE_SIZE));

    //TODO: Check that no double free occured. Perhaps by making userspace
    Ok(0)
}
pub fn physfree(physical_address: usize, size: usize) -> Result<usize> {
    enforce_root()?;
    inner_physfree(physical_address, size)
}

pub fn inner_physmap(physical_address: usize, size: usize, flags: PhysmapFlags) -> Result<usize> {
    let mut map_flags = MapFlags::MAP_SHARED | MapFlags::PROT_READ;
    map_flags.set(MapFlags::PROT_WRITE, flags.contains(PhysmapFlags::PHYSMAP_WRITE));

    let memory_type = if flags.contains(PhysmapFlags::PHYSMAP_NO_CACHE) {
        MemoryType::Uncacheable
    } else if flags.contains(PhysmapFlags::PHYSMAP_WRITE_COMBINE) {
        MemoryType::WriteCombining
    } else {
        MemoryType::Writeback
    };

    MemoryScheme::physmap(physical_address, size, map_flags, memory_type)
}
pub fn physmap(physical_address: usize, size: usize, flags: PhysmapFlags) -> Result<usize> {
    enforce_root()?;
    inner_physmap(physical_address, size, flags)
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
