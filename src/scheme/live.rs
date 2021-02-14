/// Disk scheme replacement when making live disk

use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use core::slice;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use syscall::data::Stat;
use syscall::error::*;
use syscall::flag::MODE_FILE;
use syscall::scheme::{calc_seek_offset_usize, Scheme};

struct Handle {
    path: &'static [u8],
    data: Arc<RwLock<&'static mut [u8]>>,
    mode: u16,
    seek: usize
}

pub struct DiskScheme {
    next_id: AtomicUsize,
    data: Arc<RwLock<&'static mut [u8]>>,
    handles: RwLock<BTreeMap<usize, Handle>>
}

impl DiskScheme {
    pub fn new() -> DiskScheme {
        let data;
        unsafe {
            extern {
                static mut __live_start: u8;
                static mut __live_end: u8;
            }

            let start = &mut __live_start as *mut u8;
            let end = &mut __live_end as *mut u8;

            if end as usize >= start as usize {
                data = slice::from_raw_parts_mut(start, end as usize - start as usize);
            } else {
                data = &mut [];
            };
        }

        DiskScheme {
            next_id: AtomicUsize::new(0),
            data: Arc::new(RwLock::new(data)),
            handles: RwLock::new(BTreeMap::new())
        }
    }
}

impl Scheme for DiskScheme {
    fn open(&self, _path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.handles.write().insert(id, Handle {
            path: b"0",
            data: self.data.clone(),
            mode: MODE_FILE | 0o744,
            seek: 0
        });

        Ok(id)
    }

    fn read(&self, id: usize, buffer: &mut [u8]) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let data = handle.data.read();

        let mut i = 0;
        while i < buffer.len() && handle.seek < data.len() {
            buffer[i] = data[handle.seek];
            i += 1;
            handle.seek += 1;
        }

        Ok(i)
    }

    fn write(&self, id: usize, buffer: &[u8]) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let mut data = handle.data.write();

        let mut i = 0;
        while i < buffer.len() && handle.seek < data.len() {
            data[handle.seek] = buffer[i];
            i += 1;
            handle.seek += 1;
        }

        Ok(i)
    }

    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let data = handle.data.read();
        let new_offset = calc_seek_offset_usize(handle.seek, pos, whence, data.len())?;
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
        let scheme_path = b"disk:";
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
        let data = handle.data.read();

        stat.st_mode = handle.mode;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = data.len() as u64;

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
