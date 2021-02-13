use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::str;

use crate::context;
use crate::scheme;
use crate::syscall::error::Result;

pub fn resource() -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let mut rows = Vec::new();
        {
            let contexts = context::contexts();
            for (id, context_lock) in contexts.iter() {
                let context = context_lock.read();
                rows.push((*id, context.name.read().clone(), context.files.read().clone()));
            }
        }

        for row in rows.iter() {
            let id: usize = row.0.into();
            let name = &row.1;
            let _ = writeln!(string, "{}: {}", id, name);

            for (fd, f) in row.2.iter().enumerate() {
                let file = match *f {
                    None => continue,
                    Some(ref file) => file.clone()
                };

                let description = file.description.read();

                let scheme = {
                    let schemes = scheme::schemes();
                    match schemes.get(description.scheme) {
                        Some(scheme) => scheme.clone(),
                        None => {
                            let _ = writeln!(string, "  {:>4}: {:>8} {:>8} {:>08X}: no scheme", fd, description.scheme.into(), description.number, description.flags);
                            continue;
                        }
                    }
                };

                let mut fpath = [0; 4096];
                match scheme.fpath(description.number, &mut fpath) {
                    Ok(path_len) => {
                        let fname = str::from_utf8(&fpath[..path_len]).unwrap_or("?");
                        let _ = writeln!(string, "{:>6}: {:>8} {:>8} {:>08X}: {}", fd, description.scheme.into(), description.number, description.flags, fname);
                    },
                    Err(err) => {
                        let _ = writeln!(string, "{:>6}: {:>8} {:>8} {:>08X}: {}", fd, description.scheme.into(), description.number, description.flags, err);
                    }
                }
            }
        }
    }

    Ok(string.into_bytes())
}
