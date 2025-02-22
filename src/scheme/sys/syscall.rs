use alloc::{string::String, vec::Vec};
use core::fmt::Write;

use crate::{
    context::contexts,
    syscall::{self, error::Result},
};

pub fn resource() -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let mut rows = Vec::new();
        {
            for context_ref in contexts().iter() {
                let context = context_ref.get_lock().read();
                rows.push((
                    context.pid.get(),
                    context.name.clone(),
                    context.current_syscall(),
                ));
            }
        }

        for row in rows.iter() {
            let id: usize = row.0.into();
            let name = &row.1;

            let _ = writeln!(string, "{}: {}", id, name);

            if let Some([a, b, c, d, e, f]) = row.2 {
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
