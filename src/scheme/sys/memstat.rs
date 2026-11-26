use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Write, num::NonZeroUsize, str};

use crate::{
    context::{
        self,
        memory::{AddrSpace, Grant, GrantFileRef, PageSpan, Provider},
        read_context, try_read_context,
    },
    memory::{Page, PAGE_SIZE},
    scheme::SchemeId,
    sync::CleanLockToken,
    syscall::{
        error::Result,
        flag::MapFlags,
        usercopy::{UserSlice, UserSliceRw},
    },
};
fn inner_maps(fpath_user: UserSliceRw, token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = format!(
        "{:<6} {:<33} {:<10} {:<10} {:<16} {:<8} {}\n",
        "PID", "BASE", "VIRT_SIZE", "PHYS_RSS", "TYPE", "SCHEME", "PATH"
    );

    let mut fpath_kernel = [0; PAGE_SIZE];

    struct MapRow {
        pid: usize,
        base_addr: usize,
        virt_size: usize,
        rss_size: usize,
        provider_type: &'static str,
        file_ref: Option<GrantFileRef>,
    }

    let mut rows = Vec::new();
    let mut seen_pids = alloc::collections::BTreeSet::new();

    {
        let mut contexts = context::contexts(token.downgrade());
        let (contexts, mut token) = contexts.token_split();

        for context_ref in contexts.iter() {
            let Some(context) = try_read_context(context_ref, token.downgrade()) else {
                continue;
            };
            let pid: usize = context.pid.into();
            let addr_space = context.addr_space().cloned();
            drop(context);

            if !seen_pids.insert(pid) {
                continue;
            }

            if let Ok(addr_space) = addr_space {
                let addr_space_guard = addr_space.acquire_read(token.downgrade());

                for (base, grant_info) in addr_space_guard.grants.iter() {
                    let base_addr = base.start_address().data();
                    let virt_size = grant_info.page_count() * PAGE_SIZE;

                    let mut rss_size = 0;

                    // TODO: cheaper way to get RSS size
                    for page in Page::range_inclusive(
                        base,
                        base.next_by(grant_info.page_count().saturating_sub(1)),
                    ) {
                        if addr_space_guard
                            .table
                            .utable
                            .translate(page.start_address())
                            .is_some()
                        {
                            rss_size += PAGE_SIZE;
                        }
                    }

                    let (provider_type, opt_file_ref) = match &grant_info.provider {
                        Provider::Allocated { cow_file_ref, .. } => {
                            ("Allocated", cow_file_ref.clone())
                        }
                        Provider::AllocatedShared { .. } => ("AllocShared", None),
                        Provider::PhysBorrowed { .. } => ("PhysBorrow", None),
                        Provider::External { .. } => ("External", None),
                        Provider::FmapBorrowed { file_ref, .. } => {
                            ("FmapBorrow", Some(file_ref.clone()))
                        }
                    };

                    rows.push(MapRow {
                        pid,
                        base_addr,
                        virt_size,
                        rss_size,
                        provider_type,
                        file_ref: opt_file_ref,
                    });
                }
            }
        }
    }

    rows.sort_by_key(|row| (row.pid, row.base_addr));

    for row in rows {
        let mut scheme_id_str = String::from("-");
        let mut path_str = String::from("-");

        if let Some(file_ref) = row.file_ref {
            let (number, scheme_res) = {
                let desc = file_ref.description.read(token.token());
                let scheme_res = desc.scheme_ref.upgrade();
                (desc.number, scheme_res)
            };

            if let Ok(scheme) = scheme_res {
                scheme_id_str = format!("{}", scheme.scheme_id().get());

                if let Ok(path_len) =
                    scheme.kfpath(number, fpath_user.reinterpret_unchecked(), token)
                {
                    if fpath_user.copy_to_slice(&mut fpath_kernel).is_ok() {
                        path_str = core::str::from_utf8(&fpath_kernel[..path_len])
                            .unwrap_or("?")
                            .to_string();
                    }
                }
            }
        }

        let _ = core::fmt::Write::write_fmt(
            &mut string,
            format_args!(
                "{:<6} {:016X}:{:016X} {:<10} {:<10} {:<16} {:<8} {}\n",
                row.pid,
                row.base_addr,
                row.base_addr + row.virt_size,
                super::format_bytes(row.virt_size),
                super::format_bytes(row.rss_size),
                row.provider_type,
                scheme_id_str,
                path_str
            ),
        );
    }

    Ok(string.into_bytes())
}

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let page_count = NonZeroUsize::new(1).unwrap();
    let fpath_page = {
        let addr_space = AddrSpace::current()?;
        addr_space
            .acquire_write(token.token().downgrade())
            .mmap_anywhere(
                &addr_space,
                page_count,
                MapFlags::PROT_READ | MapFlags::PROT_WRITE,
                |page, flags, mapper, flusher| {
                    Ok(Grant::zeroed(
                        PageSpan::new(page, page_count.get()),
                        flags,
                        mapper,
                        flusher,
                        false,
                    )?)
                },
            )?
    };

    let res = UserSlice::rw(fpath_page.start_address().data(), PAGE_SIZE)
        .and_then(|fpath_user| inner_maps(fpath_user, token));

    {
        let addr_space = AddrSpace::current()?;
        let unmap_res =
            addr_space.munmap(PageSpan::new(fpath_page, page_count.get()), false, token)?;
        context::memory::handle_notify_files(unmap_res, token);
    }

    res
}
