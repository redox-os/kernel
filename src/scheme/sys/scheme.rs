use alloc::vec::Vec;

use crate::{context, scheme, sync::CleanLockToken, syscall::error::Result};

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let scheme_ns = context::current().read(token.token()).ens;

    let mut data = Vec::new();

    let schemes = scheme::schemes(token.token());
    for (name, _scheme_id) in schemes.iter_name(scheme_ns) {
        data.extend_from_slice(name.as_bytes());
        data.push(b'\n');
    }

    Ok(data)
}
