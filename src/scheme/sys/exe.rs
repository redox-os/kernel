use alloc::vec::Vec;

use crate::{context, syscall::error::Result};

pub fn resource() -> Result<Vec<u8>> {
    Ok(context::current().read().name.as_bytes().to_vec())
}
