use alloc::vec::Vec;

use crate::{
    device::cpu::cpu_info,
    sync::CleanLockToken,
    syscall::error::{Error, Result, EIO},
};

pub fn resource(_token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = format!("CPUs: {}\n", crate::cpu_count());

    match cpu_info(&mut string) {
        Ok(()) => Ok(string.into_bytes()),
        Err(_) => Err(Error::new(EIO)),
    }
}
