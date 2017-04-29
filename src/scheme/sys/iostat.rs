use collections::{String, Vec};
use core::fmt::Write;
use core::str;

use context;
use scheme;
use syscall::error::Result;

pub fn resource() -> Result<Vec<u8>> {
    let mut string = String::new();

    {
        let mut rows = Vec::new();
        {
            let contexts = context::contexts();
            for (id, context_lock) in contexts.iter() {
                let context = context_lock.read();

                rows.push((*id, context.name.lock().clone(), context.files.lock().clone()));
            }
        }

        for row in rows.iter() {
            let id: usize = row.0.into();
            let name = str::from_utf8(&row.1).unwrap_or(".");
            let _ = writeln!(string, "{}: {}", id, name);

            for (fd, f) in row.2.iter().enumerate() {
                let file = match *f {
                    None => continue,
                    Some(ref file) => file.clone(),
                };

                let scheme = {
                    let schemes = scheme::schemes();
                    match schemes.get(file.scheme) {
                        Some(scheme) => scheme.clone(),
                        None => {
                            let _ = writeln!(string,
                                             "  {:>4}: {:>8} {:>8} {:>08X}: no scheme",
                                             fd,
                                             file.scheme.into(),
                                             file.number,
                                             file.flags);
                            continue;
                        }
                    }
                };

                let mut fpath = [0; 4096];
                match scheme.fpath(file.number, &mut fpath) {
                    Ok(path_len) => {
                        let fname = str::from_utf8(&fpath[..path_len]).unwrap_or("?");
                        let _ = writeln!(string,
                                         "{:>6}: {:>8} {:>8} {:>08X}: {}",
                                         fd,
                                         file.scheme.into(),
                                         file.number,
                                         file.flags,
                                         fname);
                    }
                    Err(err) => {
                        let _ = writeln!(string,
                                         "{:>6}: {:>8} {:>8} {:>08X}: {}",
                                         fd,
                                         file.scheme.into(),
                                         file.number,
                                         file.flags,
                                         err);
                    }
                }
            }
        }
    }

    Ok(string.into_bytes())
}
