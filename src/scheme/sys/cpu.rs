use alloc::vec::Vec;

use crate::device::cpu::cpu_info;
use crate::syscall::error::{Error, EIO, Result};

pub fn resource() -> Result<Vec<u8>> {
    let mut string = format!("CPUs: {}\n", crate::cpu_count());

    match cpu_info(&mut string) {
        Ok(()) => Ok(string.into_bytes()),
        Err(_) => Err(Error::new(EIO))
    }
}
