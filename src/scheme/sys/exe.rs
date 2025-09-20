use alloc::vec::Vec;

use crate::{context, sync::CleanLockToken, syscall::error::Result};

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    Ok(context::current().read().name.as_bytes().to_vec())
}
