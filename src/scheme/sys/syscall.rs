use alloc::{string::String, vec::Vec};
use core::fmt::Write;

use crate::{context, syscall, syscall::error::Result};

pub fn resource() -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let mut rows = Vec::new();
        {
            let contexts = context::contexts();
            for context_ref in contexts.iter().filter_map(|r| r.upgrade()) {
                let context = context_ref.read();
                rows.push((context.pid, context.name.clone(), context.current_syscall()));
            }
        }
        rows.sort_by_key(|row| row.0);

        for &(id, ref name, sc) in rows.iter() {
            let _ = writeln!(string, "{}: {}", id, name);

            if let Some([a, b, c, d, e, f]) = sc {
                let _ = writeln!(
                    string,
                    "  {}",
                    syscall::debug::format_call(a, b, c, d, e, f)
                );
            }
        }
    }

    Ok(string.into_bytes())
}
