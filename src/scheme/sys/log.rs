use alloc::vec::Vec;

use crate::log::LOG;
use crate::syscall::error::Result;

pub fn resource() -> Result<Vec<u8>> {
    let mut vec = Vec::new();

    if let Some(ref log) = *LOG.lock() {
        let slices = log.read();
        vec.reserve_exact(slices.0.len() + slices.1.len());
        vec.extend_from_slice(slices.0);
        vec.extend_from_slice(slices.1);
    }

    Ok(vec)
}
