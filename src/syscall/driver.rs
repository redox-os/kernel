use alloc::sync::Arc;

use crate::{
    context,
    interrupt::InterruptStack,
    paging::VirtualAddress,
    syscall::error::{Error, Result, EFAULT, EINVAL, EPERM, ESRCH},
};
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
    let addr_space = addr_space.acquire_read();

    match addr_space
        .table
        .utable
        .translate(VirtualAddress::new(virtual_address))
    {
        Some((physical_address, _)) => Ok(physical_address.data()),
        None => Err(Error::new(EFAULT)),
    }
}
