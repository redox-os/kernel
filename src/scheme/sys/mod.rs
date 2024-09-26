use ::syscall::{
    dirent::{DirEntry, DirentBuf, DirentKind},
    EIO, EISDIR, ENOTDIR,
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::RwLock;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::arch::interrupt;
use crate::{
    context::file::InternalFlags,
    syscall::{
        data::Stat,
        error::{Error, Result, EBADF, ENOENT},
        flag::{MODE_DIR, MODE_FILE},
        usercopy::UserSliceWo,
    },
};

use super::{CallerCtx, KernelScheme, OpenResult};

mod block;
mod context;
mod cpu;
mod exe;
mod iostat;
mod irq;
mod log;
mod scheme;
mod scheme_num;
mod syscall;
mod uname;

enum Handle {
    TopLevel,
    Resource { path: &'static str, data: Vec<u8> },
}

type SysFn = fn() -> Result<Vec<u8>>;

/// System information scheme
pub struct SysScheme;
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
// Using BTreeMap as hashbrown doesn't have a const constructor.
static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());

const FILES: &[(&'static str, SysFn)] = &[
    ("block", block::resource),
    ("context", context::resource),
    ("cpu", cpu::resource),
    ("exe", exe::resource),
    ("iostat", iostat::resource),
    ("irq", irq::resource),
    ("log", log::resource),
    ("scheme", scheme::resource),
    ("scheme_num", scheme_num::resource),
    ("syscall", syscall::resource),
    ("uname", uname::resource),
    ("env", || Ok(Vec::from(crate::init_env()))),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ("spurious_irq", interrupt::irq::spurious_irq_resource),
    // Disabled because the debugger is inherently unsafe and probably will break the system.
    /*
    ("trigger_debugger", || unsafe {
        crate::debugger::debugger(None);
        Ok(Vec::new())
    }),
    */
];

impl KernelScheme for SysScheme {
    fn kopen(&self, path: &str, _flags: usize, _ctx: CallerCtx) -> Result<OpenResult> {
        let path = path.trim_matches('/');

        if path.is_empty() {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

            HANDLES.write().insert(id, Handle::TopLevel);
            return Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED));
        } else {
            //Have to iterate to get the path without allocation
            for entry in FILES.iter() {
                if &entry.0 == &path {
                    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                    let data = entry.1()?;
                    HANDLES.write().insert(
                        id,
                        Handle::Resource {
                            path: entry.0,
                            data,
                        },
                    );
                    return Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED));
                }
            }
        }

        Err(Error::new(ENOENT))
    }

    fn fsize(&self, id: usize) -> Result<u64> {
        match HANDLES.read().get(&id).ok_or(Error::new(EBADF))? {
            Handle::TopLevel => Ok(0),
            Handle::Resource { data, .. } => Ok(data.len() as u64),
        }
    }

    fn close(&self, id: usize) -> Result<()> {
        HANDLES.write().remove(&id).ok_or(Error::new(EBADF))?;
        Ok(())
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handles = HANDLES.read();
        let path = match handles.get(&id).ok_or(Error::new(EBADF))? {
            Handle::TopLevel => "",
            Handle::Resource { path, .. } => path,
        };

        const FIRST: &[u8] = b"sys:";
        let mut bytes_read = buf.copy_common_bytes_from_slice(FIRST)?;

        if let Some(remaining) = buf.advance(FIRST.len()) {
            bytes_read += remaining.copy_common_bytes_from_slice(path.as_bytes())?;
        }

        Ok(bytes_read)
    }
    fn kreadoff(
        &self,
        id: usize,
        buffer: UserSliceWo,
        pos: u64,
        _flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        let Ok(pos) = usize::try_from(pos) else {
            return Ok(0);
        };

        match HANDLES.read().get(&id).ok_or(Error::new(EBADF))? {
            Handle::TopLevel => return Err(Error::new(EISDIR)),
            Handle::Resource { data, .. } => {
                let avail_buf = data.get(pos..).unwrap_or(&[]);

                buffer.copy_common_bytes_from_slice(avail_buf)
            }
        }
    }
    fn getdents(
        &self,
        id: usize,
        buf: UserSliceWo,
        header_size: u16,
        first_index: u64,
    ) -> Result<usize> {
        let Ok(first_index) = usize::try_from(first_index) else {
            return Ok(0);
        };
        match HANDLES.read().get(&id).ok_or(Error::new(EBADF))? {
            Handle::Resource { .. } => return Err(Error::new(ENOTDIR)),
            Handle::TopLevel => {
                let mut buf = DirentBuf::new(buf, header_size).ok_or(Error::new(EIO))?;
                for (this_idx, (name, _)) in FILES.iter().enumerate().skip(first_index) {
                    buf.entry(DirEntry {
                        inode: this_idx as u64,
                        next_opaque_id: this_idx as u64 + 1,
                        kind: DirentKind::Regular,
                        name,
                    })?;
                }
                Ok(buf.finalize())
            }
        }
    }

    fn kfstat(&self, id: usize, buf: UserSliceWo) -> Result<()> {
        let stat = match HANDLES.read().get(&id).ok_or(Error::new(EBADF))? {
            Handle::Resource { data, .. } => Stat {
                st_mode: 0o444 | MODE_FILE,
                st_uid: 0,
                st_gid: 0,
                st_size: data.len() as u64,
                ..Default::default()
            },
            Handle::TopLevel => Stat {
                st_mode: 0o444 | MODE_DIR,
                st_uid: 0,
                st_gid: 0,
                st_size: 0,
                ..Default::default()
            },
        };

        buf.copy_exactly(&stat)?;

        Ok(())
    }
}
