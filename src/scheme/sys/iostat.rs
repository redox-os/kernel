use crate::{
    context::{
        self,
        memory::{Grant, PageSpan},
    },
    paging::PAGE_SIZE,
    scheme,
    sync::CleanLockToken,
    syscall::{
        error::Result,
        flag::MapFlags,
        usercopy::{UserSlice, UserSliceRw},
    },
};
use alloc::{string::String, sync::Arc, vec::Vec};
use core::{fmt::Write, num::NonZeroUsize, str};

fn inner(fpath_user: UserSliceRw, token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = String::new();
    let mut fpath_kernel = [0; PAGE_SIZE];

    {
        let mut rows = Vec::new();
        {
            let mut contexts = context::contexts(token.token());
            let (contexts, mut token) = contexts.token_split();
            for context_ref in contexts.iter().filter_map(|r| r.upgrade()) {
                let context = context_ref.read(token.token());
                rows.push((context.pid, context.name, context.files.read().clone()));
            }
        }
        rows.sort_by_key(|row| row.0);

        for (id, name, fs) in rows.iter() {
            let _ = writeln!(string, "{}: {}", id, name);

            for (fd, f) in fs.enumerate() {
                let file = match *f {
                    None => continue,
                    Some(ref file) => file.clone(),
                };

                let description = file.description.read();

                let _ = write!(
                    string,
                    "{} {:>4}: {:>8} {:>8} {:>08X}: ",
                    if fd & syscall::UPPER_FDTBL_TAG == 0 {
                        " "
                    } else {
                        "U"
                    },
                    fd & !syscall::UPPER_FDTBL_TAG,
                    description.scheme.get(),
                    description.number,
                    description.flags
                );

                let scheme = {
                    let schemes = scheme::schemes(token.token());
                    match schemes.get(description.scheme) {
                        Some(scheme) => scheme.clone(),
                        None => {
                            let _ = writeln!(string, "no scheme",);
                            continue;
                        }
                    }
                };

                match scheme.kfpath(
                    description.number,
                    fpath_user.reinterpret_unchecked(),
                    token,
                ) {
                    Ok(path_len) => {
                        fpath_user.copy_to_slice(&mut fpath_kernel)?;
                        let fname = str::from_utf8(&fpath_kernel[..path_len]).unwrap_or("?");
                        let _ = writeln!(string, "{}", fname);
                    }
                    Err(err) => {
                        let _ = writeln!(string, "{}", err);
                    }
                }
            }
        }
    }

    Ok(string.into_bytes())
}

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let page_count = NonZeroUsize::new(1).unwrap();
    let fpath_page = {
        let addr_space = Arc::clone(context::current().read(token.token()).addr_space()?);
        addr_space.acquire_write().mmap(
            &addr_space,
            None,
            page_count,
            MapFlags::PROT_READ | MapFlags::PROT_WRITE,
            &mut Vec::new(),
            |page, flags, mapper, flusher| {
                let shared = false;
                Ok(Grant::zeroed(
                    PageSpan::new(page, page_count.get()),
                    flags,
                    mapper,
                    flusher,
                    shared,
                )?)
            },
        )?
    };

    let res = UserSlice::rw(fpath_page.start_address().data(), PAGE_SIZE)
        .and_then(|fpath_user| inner(fpath_user, token));

    {
        let addr_space = Arc::clone(context::current().read(token.token()).addr_space()?);
        addr_space.munmap(PageSpan::new(fpath_page, page_count.get()), false)?;
    }

    res
}
