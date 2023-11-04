use alloc::collections::BTreeMap;
use core::{mem, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use crate::context::timeout;
use crate::scheme::SchemeId;
use crate::syscall::data::TimeSpec;
use crate::syscall::error::*;
use crate::syscall::flag::{CLOCK_REALTIME, CLOCK_MONOTONIC, EventFlags};
use crate::syscall::usercopy::{UserSliceWo, UserSliceRo};
use crate::time;

use super::{KernelScheme, CallerCtx, OpenResult};

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

impl KernelScheme for TimeScheme {
    fn kopen(&self, path: &str, _flags: usize, _ctx: CallerCtx) -> Result<OpenResult> {
        let clock = path.parse::<usize>().map_err(|_| Error::new(ENOENT))?;

        match clock {
            CLOCK_REALTIME => (),
            CLOCK_MONOTONIC => (),
            _ => return Err(Error::new(ENOENT))
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.write().insert(id, clock);

        Ok(OpenResult::SchemeLocal(id))
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        let handles = self.handles.read();
        handles.get(&id).ok_or(Error::new(EBADF)).and(Ok(EventFlags::empty()))
    }

    fn fsync(&self, id: usize) -> Result<()> {
        self.handles.read().get(&id).ok_or(Error::new(EBADF))?;
        Ok(())
    }

    fn close(&self, id: usize) -> Result<()> {
        self.handles.write().remove(&id).ok_or(Error::new(EBADF)).and(Ok(()))
    }
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
