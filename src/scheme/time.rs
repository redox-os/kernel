use alloc::collections::BTreeMap;
use core::{mem, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use crate::context::timeout;
use crate::scheme::SchemeId;
use crate::syscall::data::TimeSpec;
use crate::syscall::error::*;
use crate::syscall::flag::{CLOCK_REALTIME, CLOCK_MONOTONIC, EventFlags};
use crate::syscall::scheme::Scheme;
use crate::syscall::usercopy::{UserSliceWo, UserSliceRo};
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

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        let handles = self.handles.read();
        handles.get(&id).ok_or(Error::new(EBADF)).and(Ok(EventFlags::empty()))
    }

    fn fsync(&self, id: usize) -> Result<usize> {
        let handles = self.handles.read();
        handles.get(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }

    fn close(&self, id: usize) -> Result<usize> {
        self.handles.write().remove(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
impl crate::scheme::KernelScheme for TimeScheme {
    fn kread(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let clock = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut bytes_read = 0;

        for current_chunk in buf.in_exact_chunks(mem::size_of::<TimeSpec>()) {
            let arch_time = match clock {
                CLOCK_REALTIME => time::realtime(),
                CLOCK_MONOTONIC => time::monotonic(),
                _ => return Err(Error::new(EINVAL))
            };
            let time = TimeSpec {
                tv_sec: (arch_time / time::NANOS_PER_SEC) as i64,
                tv_nsec: (arch_time % time::NANOS_PER_SEC) as i32,
            };
            current_chunk.copy_exactly(&time)?;

            bytes_read += mem::size_of::<TimeSpec>();
        }

        Ok(bytes_read)
    }

    fn kwrite(&self, id: usize, buf: UserSliceRo) -> Result<usize> {
        let clock = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut bytes_written = 0;

        for current_chunk in buf.in_exact_chunks(mem::size_of::<TimeSpec>()) {
            let time = unsafe { current_chunk.read_exact::<TimeSpec>()? };

            timeout::register(self.scheme_id, id, clock, time);

            bytes_written += mem::size_of::<TimeSpec>();
        };

        Ok(bytes_written)
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let clock = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let scheme_path = format!("time:{}", clock).into_bytes();
        let byte_count = core::cmp::min(buf.len(), scheme_path.len());
        buf.limit(byte_count).expect("must succeed").copy_from_slice(&scheme_path)?;
        Ok(byte_count)
    }

}
