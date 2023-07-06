use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::str;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use crate::syscall::data::Stat;
use crate::syscall::error::{Error, EBADF, ENOENT, Result};
use crate::syscall::flag::{MODE_DIR, MODE_FILE};
use crate::syscall::scheme::{calc_seek_offset_usize, Scheme};
use crate::arch::interrupt;
use crate::syscall::usercopy::UserSliceWo;

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
    seek: usize
}

type SysFn = fn() -> Result<Vec<u8>>;

/// System information scheme
pub struct SysScheme {
    next_id: AtomicUsize,
    files: BTreeMap<&'static str, SysFn>,
    handles: RwLock<BTreeMap<usize, Handle>>
}

impl SysScheme {
    pub fn new() -> SysScheme {
        let mut files: BTreeMap<&'static str, SysFn> = BTreeMap::new();

        files.insert("block", block::resource);
        files.insert("context", context::resource);
        files.insert("cpu", cpu::resource);
        files.insert("exe", exe::resource);
        files.insert("iostat", iostat::resource);
        files.insert("irq", irq::resource);
        files.insert("log", log::resource);
        files.insert("scheme", scheme::resource);
        files.insert("scheme_num", scheme_num::resource);
        files.insert("syscall", syscall::resource);
        files.insert("uname", uname::resource);
        files.insert("env", || Ok(Vec::from(crate::init_env())));
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        files.insert("spurious_irq", interrupt::irq::spurious_irq_resource);

        SysScheme {
            next_id: AtomicUsize::new(0),
            files,
            handles: RwLock::new(BTreeMap::new())
        }
    }
}

impl Scheme for SysScheme {
    fn open(&self, path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let path = path.trim_matches('/');

        if path.is_empty() {
            let mut data = Vec::new();
            for entry in self.files.iter() {
                if ! data.is_empty() {
                    data.push(b'\n');
                }
                data.extend_from_slice(entry.0.as_bytes());
            }

            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            self.handles.write().insert(id, Handle {
                path: "",
                data,
                mode: MODE_DIR | 0o444,
                seek: 0
            });
            return Ok(id)
        } else {
            //Have to iterate to get the path without allocation
            for entry in self.files.iter() {
                if entry.0 == &path {
                    let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                    let data = entry.1()?;
                    self.handles.write().insert(id, Handle {
                        path: entry.0,
                        data,
                        mode: MODE_FILE | 0o444,
                        seek: 0
                    });
                    return Ok(id)
                }
            }
        }

        Err(Error::new(ENOENT))
    }

    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let new_offset = calc_seek_offset_usize(handle.seek, pos, whence, handle.data.len())?;
        handle.seek = new_offset as usize;
        Ok(new_offset)
    }

    fn fsync(&self, _id: usize) -> Result<usize> {
        Ok(0)
    }

    fn close(&self, id: usize) -> Result<usize> {
        self.handles.write().remove(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
impl crate::scheme::KernelScheme for SysScheme {
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        const FIRST: &[u8] = b"sys:";
        let mut bytes_read = buf.copy_common_bytes_from_slice(FIRST)?;

        if let Some(remaining) = buf.advance(FIRST.len()) {
            bytes_read += remaining.copy_common_bytes_from_slice(handle.path.as_bytes())?;
        }


        Ok(bytes_read)
    }
    fn kread(&self, id: usize, buffer: UserSliceWo) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let avail_buf = handle.data.get(handle.seek..).unwrap_or(&[]);

        let byte_count = buffer.copy_common_bytes_from_slice(avail_buf)?;

        handle.seek = handle.seek.saturating_add(byte_count);
        Ok(byte_count)
    }

    fn kfstat(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        buf.copy_exactly(&Stat {
            st_mode: handle.mode,
            st_uid: 0,
            st_gid: 0,
            st_size: handle.data.len() as u64,
            ..Default::default()
        })?;

        Ok(0)
    }
}
