use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::str;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use crate::syscall::data::Stat;
use crate::syscall::error::{Error, EBADF, ENOENT, Result};
use crate::syscall::flag::{MODE_DIR, MODE_FILE};
use crate::syscall::scheme::{calc_seek_offset_usize, Scheme};
use crate::arch::interrupt::irq;

mod block;
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
    path: &'static str,
    data: Vec<u8>,
    mode: u16,
    seek: usize
}

type SysFn = dyn Fn() -> Result<Vec<u8>> + Send + Sync;

/// System information scheme
pub struct SysScheme {
    next_id: AtomicUsize,
    files: BTreeMap<&'static str, Box<SysFn>>,
    handles: RwLock<BTreeMap<usize, Handle>>
}

impl SysScheme {
    pub fn new() -> SysScheme {
        let mut files: BTreeMap<&'static str, Box<SysFn>> = BTreeMap::new();

        files.insert("block", Box::new(block::resource));
        files.insert("context", Box::new(context::resource));
        files.insert("cpu", Box::new(cpu::resource));
        files.insert("exe", Box::new(exe::resource));
        files.insert("iostat", Box::new(iostat::resource));
        files.insert("log", Box::new(log::resource));
        files.insert("scheme", Box::new(scheme::resource));
        files.insert("scheme_num", Box::new(scheme_num::resource));
        files.insert("syscall", Box::new(syscall::resource));
        files.insert("uname", Box::new(uname::resource));
        #[cfg(target_arch = "x86_64")]
        files.insert("spurious_irq", Box::new(irq::spurious_irq_resource));

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
                        data: data,
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

    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let new_offset = calc_seek_offset_usize(handle.seek, pos, whence, handle.data.len())?;
        handle.seek = new_offset as usize;
        Ok(new_offset)
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

        let path = handle.path.as_bytes();
        let mut j = 0;
        while i < buf.len() && j < path.len() {
            buf[i] = path[j];
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
