use alloc::{
    boxed::Box,
    vec::Vec,
};

use crate::context;
use crate::syscall::error::{Error, ESRCH, Result};

pub fn resource() -> Result<Vec<u8>> {
    let name = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let name = context.name.read();
        let name_bytes: Box<[u8]> = name.clone().into();
        name_bytes.into_vec()
    };
    Ok(name)
}
