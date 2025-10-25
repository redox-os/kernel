// TODO: This scheme can be simplified significantly, and through it, several other APIs where it's
// dubious whether they require dedicated schemes (like irq, dtb, acpi). In particular, the kernel
// could abandon the filesystem-like APIs here in favor of SYS_CALL, and instead let userspace wrap
// those to say shell-accessible fs-like APIs.

use ::syscall::{
    dirent::{DirEntry, DirentBuf, DirentKind},
    EBADFD, EINVAL, EIO, EISDIR, ENOTDIR, EPERM,
};
use alloc::vec::Vec;
use core::{
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::arch::interrupt;
use crate::{
    context::file::InternalFlags,
    sync::{CleanLockToken, RwLock, L1},
    syscall::{
        data::Stat,
        error::{Error, Result, EBADF, ENOENT},
        flag::{MODE_DIR, MODE_FILE},
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

use super::{CallerCtx, KernelScheme, OpenResult};

mod block;
mod context;
mod cpu;

#[cfg(feature = "sys_fdstat")]
mod fdstat;

mod exe;
mod iostat;
mod irq;
mod log;
mod scheme;
mod scheme_num;
mod stat;
mod syscall;
mod uname;

enum Handle {
    TopLevel,
    Resource {
        path: &'static str,
        data: Option<Vec<u8>>,
    },
}

enum Kind {
    Rd(fn(&mut CleanLockToken) -> Result<Vec<u8>>),
    Wr(fn(&[u8], &mut CleanLockToken) -> Result<usize>),
}
use Kind::*;

/// System information scheme
pub struct SysScheme;
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
static HANDLES: RwLock<L1, HashMap<usize, Handle>> =
    RwLock::new(HashMap::with_hasher(DefaultHashBuilder::new()));

const FILES: &[(&str, Kind)] = &[
    ("block", Rd(block::resource)),
    ("context", Rd(context::resource)),
    ("cpu", Rd(cpu::resource)),
    #[cfg(feature = "sys_fdstat")]
    ("fdstat", Rd(fdstat::resource)),
    ("exe", Rd(exe::resource)),
    ("iostat", Rd(iostat::resource)),
    ("irq", Rd(irq::resource)),
    ("log", Rd(log::resource)),
    ("scheme", Rd(scheme::resource)),
    ("scheme_num", Rd(scheme_num::resource)),
    ("syscall", Rd(syscall::resource)),
    ("uname", Rd(uname::resource)),
    ("env", Rd(|_| Ok(Vec::from(crate::init_env())))),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ("spurious_irq", Rd(interrupt::irq::spurious_irq_resource)),
    ("stat", Rd(stat::resource)),
    // Disabled because the debugger is inherently unsafe and probably will break the system.
    /*
    ("trigger_debugger", Rd(|token| unsafe {
        crate::debugger::debugger(None, token);
        Ok(Vec::new())
    })),
    */
    (
        "update_time_offset",
        Wr(crate::time::sys_update_time_offset),
    ),
    (
        "kstop",
        Wr(|arg, token| unsafe {
            match arg.trim_ascii() {
                b"shutdown" => crate::stop::kstop(token),
                b"reset" => crate::stop::kreset(),
                b"emergency_reset" => crate::stop::emergency_reset(),
                _ => Err(Error::new(EINVAL)),
            }
        }),
    ),
];

impl KernelScheme for SysScheme {
    fn kopen(
        &self,
        path: &str,
        _flags: usize,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let path = path.trim_matches('/');

        if path.is_empty() {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

            HANDLES.write(token.token()).insert(id, Handle::TopLevel);

            Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED))
        } else {
            //Have to iterate to get the path without allocation
            let entry = FILES
                .iter()
                .find(|(entry_path, _)| *entry_path == path)
                .ok_or(Error::new(ENOENT))?;

            if matches!(entry.1, Wr(_)) && ctx.uid != 0 {
                return Err(Error::new(EPERM));
            }

            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let data = match entry.1 {
                Rd(r) => Some(r(token)?),
                Wr(_) => None,
            };
            HANDLES.write(token.token()).insert(
                id,
                Handle::Resource {
                    path: entry.0,
                    data,
                },
            );
            Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED))
        }
    }

    fn fsize(&self, id: usize, token: &mut CleanLockToken) -> Result<u64> {
        match HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?
        {
            Handle::TopLevel => Ok(0),
            Handle::Resource { data, .. } => Ok(data.as_ref().map_or(0, |d| d.len() as u64)),
        }
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        HANDLES
            .write(token.token())
            .remove(&id)
            .ok_or(Error::new(EBADF))?;
        Ok(())
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        let handles = HANDLES.read(token.token());
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
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let Ok(pos) = usize::try_from(pos) else {
            return Ok(0);
        };

        match HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?
        {
            Handle::TopLevel | Handle::Resource { data: None, .. } => Err(Error::new(EISDIR)),
            &Handle::Resource {
                data: Some(ref data),
                ..
            } => {
                let avail_buf = data.get(pos..).unwrap_or(&[]);

                buffer.copy_common_bytes_from_slice(avail_buf)
            }
        }
    }
    fn kwriteoff(
        &self,
        id: usize,
        buffer: UserSliceRo,
        _pos: u64,
        _flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let (handler, intermediate, len) = match HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?
        {
            Handle::TopLevel | Handle::Resource { data: Some(_), .. } => {
                return Err(Error::new(EISDIR))
            }
            Handle::Resource { data: None, path } => {
                let mut intermediate = [0_u8; 256];
                let len = buffer.copy_common_bytes_to_slice(&mut intermediate)?;
                let (_, Wr(handler)) = FILES
                    .iter()
                    .find(|(entry_path, _)| entry_path == path)
                    .ok_or(Error::new(EBADFD))?
                else {
                    return Err(Error::new(EBADFD))?;
                };
                (handler, intermediate, len)
            }
        };
        handler(&intermediate[..len], token)
    }
    fn getdents(
        &self,
        id: usize,
        buf: UserSliceWo,
        header_size: u16,
        first_index: u64,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let Ok(first_index) = usize::try_from(first_index) else {
            return Ok(0);
        };
        match HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?
        {
            Handle::Resource { .. } => Err(Error::new(ENOTDIR)),
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

    fn kfstat(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<()> {
        let stat = match HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?
        {
            Handle::Resource { data, .. } => Stat {
                st_mode: 0o666 | MODE_FILE,
                st_uid: 0,
                st_gid: 0,
                st_size: data.as_ref().map_or(0, |d| d.len() as u64),
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
