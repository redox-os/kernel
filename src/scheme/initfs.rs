use alloc::collections::BTreeMap;
use core::str;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use crate::syscall::data::Stat;
use crate::syscall::error::*;
use crate::syscall::flag::{MODE_DIR, MODE_FILE};
use crate::syscall::scheme::{calc_seek_offset_usize, Scheme};

#[cfg(test)]
mod gen {
    use alloc::collections::BTreeMap;
    pub fn gen() -> BTreeMap<&'static [u8], (&'static [u8], bool)> { BTreeMap::new() }
}

#[cfg(not(test))]
include!(concat!(env!("OUT_DIR"), "/gen.rs"));

struct Handle {
    path: &'static [u8],
    data: &'static [u8],
    mode: u16,
    seek: usize
}

pub struct InitFsScheme {
    next_id: AtomicUsize,
    files: BTreeMap<&'static [u8], (&'static [u8], bool)>,
    handles: RwLock<BTreeMap<usize, Handle>>
}

impl InitFsScheme {
    pub fn new() -> InitFsScheme {
        InitFsScheme {
            next_id: AtomicUsize::new(0),
            files: gen::gen(),
            handles: RwLock::new(BTreeMap::new())
        }
    }
}

impl Scheme for InitFsScheme {
    fn open(&self, path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let path_trimmed = path.trim_matches('/');

        //Have to iterate to get the path without allocation
        for entry in self.files.iter() {
            if entry.0 == &path_trimmed.as_bytes() {
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                self.handles.write().insert(id, Handle {
                    path: entry.0,
                    data: (entry.1).0,
                    mode: if (entry.1).1 { MODE_DIR |  0o755 } else { MODE_FILE | 0o744 },
                    seek: 0
                });

                return Ok(id);
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

    fn fcntl(&self, id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        let handles = self.handles.read();
        let _handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        Ok(0)
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        //TODO: Copy scheme part in kernel
        let mut i = 0;
        let scheme_path = b"initfs:";
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

    fn fsync(&self, id: usize) -> Result<usize> {
        let handles = self.handles.read();
        let _handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        Ok(0)
    }

    fn close(&self, id: usize) -> Result<usize> {
        self.handles.write().remove(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
