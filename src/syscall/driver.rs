use alloc::sync::Arc;

use crate::interrupt::InterruptStack;
use crate::paging::VirtualAddress;
use crate::context;
use crate::scheme::memory::{MemoryScheme, MemoryType};
use crate::syscall::error::{Error, EFAULT, EINVAL, EPERM, ESRCH, Result};
use crate::syscall::flag::{MapFlags, PhysmapFlags};

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

pub fn virttophys(virtual_address: usize) -> Result<usize> {
    enforce_root()?;

    let addr_space = Arc::clone(context::current()?.read().addr_space()?);
    let addr_space = addr_space.read();

    match addr_space.table.utable.translate(VirtualAddress::new(virtual_address)) {
        Some((physical_address, _)) => Ok(physical_address.data()),
        None => Err(Error::new(EFAULT))
    }
}

// TODO: Remove:
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
