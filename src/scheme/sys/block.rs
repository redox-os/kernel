use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::context;
use crate::syscall::error::Result;

pub fn resource() -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let mut rows = Vec::new();
        {
            let contexts = context::contexts();
            for (id, context_lock) in contexts.iter() {
                let context = context_lock.read();
                rows.push((*id, context.name.read().clone(), context.status_reason));
            }
        }

        for row in rows.iter() {
            let id: usize = row.0.into();
            let name = &row.1;

            let _ = writeln!(string, "{}: {}", id, name);

            if ! row.2.is_empty() {
                let _ = writeln!(string, "  {}", row.2);
            }
        }
    }

    Ok(string.into_bytes())
}
