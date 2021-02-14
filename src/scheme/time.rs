use alloc::collections::BTreeMap;
use core::{mem, slice, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use crate::context::timeout;
use crate::scheme::SchemeId;
use crate::syscall::data::TimeSpec;
use crate::syscall::error::*;
use crate::syscall::flag::{CLOCK_REALTIME, CLOCK_MONOTONIC, EventFlags};
use crate::syscall::scheme::Scheme;
use crate::time;

pub struct TimeScheme {
    scheme_id: SchemeId,
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, usize>>
}

impl TimeScheme {
    pub fn new(scheme_id: SchemeId) -> TimeScheme {
        TimeScheme {
            scheme_id,
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new())
        }
    }
}

impl Scheme for TimeScheme {
    fn open(&self, path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let clock = path.parse::<usize>().or(Err(Error::new(ENOENT)))?;

        match clock {
            CLOCK_REALTIME => (),
            CLOCK_MONOTONIC => (),
            _ => return Err(Error::new(ENOENT))
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.handles.write().insert(id, clock);

        Ok(id)
    }

    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let clock = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let time_buf = unsafe { slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut TimeSpec, buf.len()/mem::size_of::<TimeSpec>()) };

        let mut i = 0;
        while i < time_buf.len() {
            let arch_time = match clock {
                CLOCK_REALTIME => time::realtime(),
                CLOCK_MONOTONIC => time::monotonic(),
                _ => return Err(Error::new(EINVAL))
            };
            time_buf[i].tv_sec = arch_time.0 as i64;
            time_buf[i].tv_nsec = arch_time.1 as i32;
            i += 1;
        }

        Ok(i * mem::size_of::<TimeSpec>())
    }

    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        let clock = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let time_buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const TimeSpec, buf.len()/mem::size_of::<TimeSpec>()) };

        let mut i = 0;
        while i < time_buf.len() {
            let time = time_buf[i];
            timeout::register(self.scheme_id, id, clock, time);
            i += 1;
        }

        Ok(i * mem::size_of::<TimeSpec>())
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        let handles = self.handles.read();
        handles.get(&id).ok_or(Error::new(EBADF)).and(Ok(EventFlags::empty()))
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let clock = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut i = 0;
        let scheme_path = format!("time:{}", clock).into_bytes();
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }
        Ok(i)
    }

    fn fsync(&self, id: usize) -> Result<usize> {
        let handles = self.handles.read();
        handles.get(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }

    fn close(&self, id: usize) -> Result<usize> {
        self.handles.write().remove(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
