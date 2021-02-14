use alloc::vec::Vec;

use crate::context;
use crate::scheme;
use crate::syscall::error::{Error, ESRCH, Result};

pub fn resource() -> Result<Vec<u8>> {
    let scheme_ns = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.ens
    };

    let mut data = Vec::new();

    let schemes = scheme::schemes();
    for (name, _scheme_id) in schemes.iter_name(scheme_ns) {
        data.extend_from_slice(name.as_bytes());
        data.push(b'\n');
    }

    Ok(data)
}
