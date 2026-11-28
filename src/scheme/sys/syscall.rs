use alloc::{string::String, vec::Vec};
use core::fmt::Write;

use crate::{
    context,
    sync::CleanLockToken,
    syscall::{self, error::Result},
};

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let mut rows = Vec::new();
        {
            let mut contexts = context::contexts(token.downgrade());
            let (contexts, mut token) = contexts.token_split();
            for context_ref in contexts.iter() {
                let Some(context) = context::try_read_context(context_ref, token.downgrade())
                else {
                    continue;
                };
                rows.push((context.pid, context.name, context.current_syscall()));
            }
        }
        rows.sort_by_key(|row| row.0);

        for &(id, ref name, sc) in rows.iter() {
            let _ = writeln!(string, "{}: {}", id, name);

            if let Some([a, b, c, d, e, f, g]) = sc {
                let _ = writeln!(
                    string,
                    "  {}",
                    syscall::debug::format_call(a, b, c, d, e, f, g)
                );
            }
        }
    }

    Ok(string.into_bytes())
}
