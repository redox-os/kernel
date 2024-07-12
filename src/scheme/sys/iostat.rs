use crate::{context, scheme, syscall::error::Result};
use alloc::{string::String, vec::Vec};
use core::fmt::Write;

pub fn resource() -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let mut rows = Vec::new();
        {
            let contexts = context::contexts();
            for context_ref in contexts.iter().filter_map(|r| r.upgrade()) {
                let context = context_ref.read();
                rows.push((
                    context.pid,
                    context.name.clone(),
                    context.files.read().clone(),
                ));
            }
        }

        for row in rows.iter() {
            let id: usize = row.0.into();
            let name = &row.1;
            let _ = writeln!(string, "{}: {}", id, name);

            for (fd, f) in row.2.iter().enumerate() {
                let file = match *f {
                    None => continue,
                    Some(ref file) => file.clone(),
                };

                let description = file.description.read();

                let _scheme = {
                    let schemes = scheme::schemes();
                    match schemes.get(description.scheme) {
                        Some(scheme) => scheme.clone(),
                        None => {
                            let _ = writeln!(
                                string,
                                "  {:>4}: {:>8} {:>8} {:>08X}: no scheme",
                                fd,
                                description.scheme.get(),
                                description.number,
                                description.flags
                            );
                            continue;
                        }
                    }
                };

                /*
                let mut fpath = [0; 4096];
                match scheme.fpath(description.number, &mut fpath) {
                    Ok(path_len) => {
                        let fname = str::from_utf8(&fpath[..path_len]).unwrap_or("?");
                        let _ = writeln!(string, "{:>6}: {:>8} {:>8} {:>08X}: {}", fd, description.scheme.get(), description.number, description.flags, fname);
                    },
                    Err(err) => {
                        let _ = writeln!(string, "{:>6}: {:>8} {:>8} {:>08X}: {}", fd, description.scheme.get(), description.number, description.flags, err);
                    }
                }
                */
            }
        }
    }

    Ok(string.into_bytes())
}
