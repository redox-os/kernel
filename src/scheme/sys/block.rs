use alloc::{string::String, vec::Vec};
use core::fmt::Write;

use crate::{context, sync::CleanLockToken, syscall::error::Result};

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let mut rows = Vec::new();
        {
            let mut contexts = context::contexts(token.token());
            let (contexts, mut token) = contexts.token_split();
            for context_lock in contexts.iter().filter_map(|r| r.upgrade()) {
                let context = context_lock.read(token.token());
                rows.push((context.pid, context.name, context.status_reason));
            }
        }
        rows.sort_by_key(|row| row.0);

        for row in rows.iter() {
            let id: usize = row.0;
            let name = &row.1;

            let _ = writeln!(string, "{}: {}", id, name);

            if !row.2.is_empty() {
                let _ = writeln!(string, "  {}", row.2);
            }
        }
    }

    Ok(string.into_bytes())
}
