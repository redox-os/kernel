use alloc::{string::String, vec::Vec};
use core::fmt::Write;

use crate::{scheme::irq::Irq, sync::CleanLockToken, syscall::error::Result};

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let counts = crate::scheme::irq::irq_stat(token);
        for (i, count) in counts.iter().enumerate() {
            if *count > 0 {
                let _ = writeln!(string, "{}: {}", i, *count);
            }
        }
    }

    Ok(string.into_bytes())
}
