use alloc::vec::Vec;

use crate::{context::process, scheme, syscall::error::Result};

pub fn resource() -> Result<Vec<u8>> {
    let scheme_ns = process::current()?.read().ens;

    let mut data = Vec::new();

    let schemes = scheme::schemes();
    for (name, _scheme_id) in schemes.iter_name(scheme_ns) {
        data.extend_from_slice(name.as_bytes());
        data.push(b'\n');
    }

    Ok(data)
}
