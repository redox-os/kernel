use alloc::vec::Vec;

use crate::context;
use crate::syscall::error::Result;

pub fn resource() -> Result<Vec<u8>> {
    Ok(context::current()?.read().name.clone().into_owned().into_bytes())
}
