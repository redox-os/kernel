use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::{cmp, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use crate::syscall::data::Stat;
use crate::syscall::error::{Error, EBADF, EINVAL, ENOENT, Result};
use crate::syscall::flag::{MODE_DIR, MODE_FILE, SEEK_CUR, SEEK_END, SEEK_SET};
use crate::syscall::scheme::Scheme;

mod context;
mod cpu;
mod exe;
mod iostat;
mod log;
mod scheme;
mod scheme_num;
mod syscall;
mod uname;

struct Handle {
    path: &'static [u8],
    data: Vec<u8>,
    mode: u16,
    seek: usize
}

type SysFn = Fn() -> Result<Vec<u8>> + Send + Sync;

/// System information scheme
pub struct SysScheme {
    next_id: AtomicUsize,
    files: BTreeMap<&'static [u8], Box<SysFn>>,
    handles: RwLock<BTreeMap<usize, Handle>>
}

impl SysScheme {
    pub fn new() -> SysScheme {
        let mut files: BTreeMap<&'static [u8], Box<SysFn>> = BTreeMap::new();

        files.insert(b"context", Box::new(move || context::resource()));
        files.insert(b"cpu", Box::new(move || cpu::resource()));
        files.insert(b"exe", Box::new(move || exe::resource()));
        files.insert(b"iostat", Box::new(move || iostat::resource()));
        files.insert(b"log", Box::new(move || log::resource()));
        files.insert(b"scheme", Box::new(move || scheme::resource()));
        files.insert(b"scheme_num", Box::new(move || scheme_num::resource()));
        files.insert(b"syscall", Box::new(move || syscall::resource()));
        files.insert(b"uname", Box::new(move || uname::resource()));

        SysScheme {
            next_id: AtomicUsize::new(0),
            files: files,
            handles: RwLock::new(BTreeMap::new())
        }
    }
}

impl Scheme for SysScheme {
    fn open(&self, path: &[u8], _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let path_utf8 = str::from_utf8(path).or(Err(Error::new(ENOENT)))?;
        let path_trimmed = path_utf8.trim_matches('/');

        if path_trimmed.is_empty() {
            let mut data = Vec::new();
            for entry in self.files.iter() {
                if ! data.is_empty() {
                    data.push(b'\n');
                }
                data.extend_from_slice(entry.0);
            }

            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            self.handles.write().insert(id, Handle {
                path: b"",
                data: data,
                mode: MODE_DIR | 0o444,
                seek: 0
            });
            return Ok(id)
        } else {
            //Have to iterate to get the path without allocation
            for entry in self.files.iter() {
                if entry.0 == &path_trimmed.as_bytes() {
                    let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                    self.handles.write().insert(id, Handle {
                        path: entry.0,
                        data: entry.1()?,
                        mode: MODE_FILE | 0o444,
                        seek: 0
                    });
                    return Ok(id)
                }
            }
        }

        Err(Error::new(ENOENT))
    }

    fn read(&self, id: usize, buffer: &mut [u8]) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let mut i = 0;
        while i < buffer.len() && handle.seek < handle.data.len() {
            buffer[i] = handle.data[handle.seek];
            i += 1;
            handle.seek += 1;
        }

        Ok(i)
    }

    fn seek(&self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        handle.seek = match whence {
            SEEK_SET => cmp::min(handle.data.len(), pos),
            SEEK_CUR => cmp::max(0, cmp::min(handle.data.len() as isize, handle.seek as isize + pos as isize)) as usize,
            SEEK_END => cmp::max(0, cmp::min(handle.data.len() as isize, handle.data.len() as isize + pos as isize)) as usize,
            _ => return Err(Error::new(EINVAL))
        };

        Ok(handle.seek)
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        let mut i = 0;
        let scheme_path = b"sys:";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }

        let mut j = 0;
        while i < buf.len() && j < handle.path.len() {
            buf[i] = handle.path[j];
            i += 1;
            j += 1;
        }

        Ok(i)
    }

    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        stat.st_mode = handle.mode;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = handle.data.len() as u64;

        Ok(0)
    }

    fn fsync(&self, _id: usize) -> Result<usize> {
        Ok(0)
    }

    fn close(&self, id: usize) -> Result<usize> {
        self.handles.write().remove(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
