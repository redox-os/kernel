use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::RwLock;

use crate::{
    arch::interrupt,
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

struct Handle {
    path: &'static str,
    data: Vec<u8>,
    mode: u16,
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
            let mut data = Vec::new();
            for entry in FILES.iter() {
                if !data.is_empty() {
                    data.push(b'\n');
                }
                data.extend_from_slice(entry.0.as_bytes());
            }

            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            HANDLES.write().insert(
                id,
                Handle {
                    path: "",
                    data,
                    mode: MODE_DIR | 0o444,
                },
            );
            return Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED));
        } else {
            //Have to iterate to get the path without allocation
            for entry in FILES.iter() {
                if &entry.0 == &path {
                    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                    let data = entry.1()?;
                    HANDLES.write().insert(
                        id,
                        Handle {
                            path: entry.0,
                            data,
                            mode: MODE_FILE | 0o444,
                        },
                    );
                    return Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED));
                }
            }
        }

        Err(Error::new(ENOENT))
    }

    fn fsize(&self, id: usize) -> Result<u64> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        Ok(handle.data.len() as u64)
    }

    fn fsync(&self, _id: usize) -> Result<()> {
        Ok(())
    }

    fn close(&self, id: usize) -> Result<()> {
        HANDLES
            .write()
            .remove(&id)
            .ok_or(Error::new(EBADF))
            .and(Ok(()))
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        const FIRST: &[u8] = b"sys:";
        let mut bytes_read = buf.copy_common_bytes_from_slice(FIRST)?;

        if let Some(remaining) = buf.advance(FIRST.len()) {
            bytes_read += remaining.copy_common_bytes_from_slice(handle.path.as_bytes())?;
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

        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let avail_buf = handle.data.get(pos..).unwrap_or(&[]);

        buffer.copy_common_bytes_from_slice(avail_buf)
    }

    fn kfstat(&self, id: usize, buf: UserSliceWo) -> Result<()> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        buf.copy_exactly(&Stat {
            st_mode: handle.mode,
            st_uid: 0,
            st_gid: 0,
            st_size: handle.data.len() as u64,
            ..Default::default()
        })?;

        Ok(())
    }
}
