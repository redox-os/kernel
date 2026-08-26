use crate::{
    context::{
        self,
        memory::{handle_notify_files, Grant, PageSpan},
    },
    memory::PAGE_SIZE,
    scheme::{self, SchemeId},
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
            let mut contexts = context::contexts(token.downgrade());
            let (contexts, mut token) = contexts.token_split();
            for context_ref in contexts.iter() {
                let mut current = context_ref.read(token.token());
                let (context, mut token) = current.token_split();
                rows.push((
                    context.pid,
                    context.name,
                    context.files.read(token.token()).clone(),
                ));
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

                let (scheme_res, number, flags) = {
                    let desc = file.description.read(token.token());
                    (desc.scheme_ref.upgrade(), desc.number, desc.flags)
                };

                let scheme_id = scheme_res
                    .as_ref()
                    .map_or(SchemeId::new(!0), |s| s.scheme_id());

                let _ = write!(
                    string,
                    "{} {:>4}: {:>8} {:>8} {:>08X}: ",
                    if fd & syscall::UPPER_FDTBL_TAG == 0 {
                        " "
                    } else {
                        "U"
                    },
                    fd & !syscall::UPPER_FDTBL_TAG,
                    scheme_id.get(),
                    number,
                    flags
                );

                let Ok(scheme) = scheme_res else {
                    let _ = writeln!(string, "no scheme",);
                    continue;
                };

                match scheme.kfpath(number, fpath_user.reinterpret_unchecked(), token) {
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
        addr_space
            .acquire_write(token.token().downgrade())
            .mmap_anywhere(
                &addr_space,
                page_count,
                MapFlags::PROT_READ | MapFlags::PROT_WRITE,
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
        let res = addr_space.munmap(PageSpan::new(fpath_page, page_count.get()), false, token)?;
        handle_notify_files(res, token);
    }

    res
}
