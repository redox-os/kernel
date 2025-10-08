use alloc::vec::Vec;

use crate::{context, sync::CleanLockToken, syscall::error::Result};

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    Ok(context::current()
        .read(token.token())
        .name
        .as_bytes()
        .to_vec())
}
