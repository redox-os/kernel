use alloc::sync::Arc;

use crate::{
    context::{self, process},
    paging::VirtualAddress,
    syscall::error::{Error, Result, EFAULT, EPERM},
};
fn enforce_root() -> Result<()> {
    if process::current()?.read().euid != 0 {
        return Err(Error::new(EPERM));
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn iopl(_level: usize) -> Result<usize> {
    Err(Error::new(syscall::error::ENOSYS))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn iopl(level: usize) -> Result<usize> {
    enforce_root()?;

    context::current()
        .write()
        .set_userspace_io_allowed(level >= 3);

    Ok(0)
}

pub fn virttophys(virtual_address: usize) -> Result<usize> {
    enforce_root()?;

    let addr_space = Arc::clone(context::current().read().addr_space()?);
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
