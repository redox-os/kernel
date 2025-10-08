use alloc::{string::String, vec::Vec};
use core::fmt::Write;

use crate::{sync::CleanLockToken, syscall::error::Result};

pub fn resource(_token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let counts = crate::scheme::irq::COUNTS.lock();
        for (i, count) in counts.iter().enumerate() {
            let _ = writeln!(string, "{}: {}", i, count);
        }
    }

    Ok(string.into_bytes())
}
