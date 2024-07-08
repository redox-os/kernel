use alloc::collections::BTreeMap;
use core::{
    mem, str,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::RwLock;

use crate::{
    context::{file::InternalFlags, timeout},
    syscall::{
        data::TimeSpec,
        error::*,
        flag::{EventFlags, CLOCK_MONOTONIC, CLOCK_REALTIME},
        usercopy::{UserSliceRo, UserSliceWo},
    },
    time,
};

use super::{CallerCtx, GlobalSchemes, KernelScheme, OpenResult};

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
// Using BTreeMap as hashbrown doesn't have a const constructor.
static HANDLES: RwLock<BTreeMap<usize, usize>> = RwLock::new(BTreeMap::new());

pub struct TimeScheme;

impl KernelScheme for TimeScheme {
    fn kopen(&self, path: &str, _flags: usize, _ctx: CallerCtx) -> Result<OpenResult> {
        let clock = path.parse::<usize>().map_err(|_| Error::new(ENOENT))?;

        match clock {
            CLOCK_REALTIME => (),
            CLOCK_MONOTONIC => (),
            _ => return Err(Error::new(ENOENT)),
        }

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        HANDLES.write().insert(id, clock);

        Ok(OpenResult::SchemeLocal(id, InternalFlags::empty()))
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        HANDLES
            .read()
            .get(&id)
            .ok_or(Error::new(EBADF))
            .and(Ok(EventFlags::empty()))
    }

    fn fsync(&self, id: usize) -> Result<()> {
        HANDLES.read().get(&id).ok_or(Error::new(EBADF))?;
        Ok(())
    }

    fn close(&self, id: usize) -> Result<()> {
        HANDLES
            .write()
            .remove(&id)
            .ok_or(Error::new(EBADF))
            .and(Ok(()))
    }
    fn kread(&self, id: usize, buf: UserSliceWo, _flags: u32, _stored_flags: u32) -> Result<usize> {
        let clock = *HANDLES.read().get(&id).ok_or(Error::new(EBADF))?;

        let mut bytes_read = 0;

        for current_chunk in buf.in_exact_chunks(mem::size_of::<TimeSpec>()) {
            let arch_time = match clock {
                CLOCK_REALTIME => time::realtime(),
                CLOCK_MONOTONIC => time::monotonic(),
                _ => return Err(Error::new(EINVAL)),
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

    fn kwrite(
        &self,
        id: usize,
        buf: UserSliceRo,
        _flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        let clock = *HANDLES.read().get(&id).ok_or(Error::new(EBADF))?;

        let mut bytes_written = 0;

        for current_chunk in buf.in_exact_chunks(mem::size_of::<TimeSpec>()) {
            let time = unsafe { current_chunk.read_exact::<TimeSpec>()? };

            timeout::register(GlobalSchemes::Time.scheme_id(), id, clock, time);

            bytes_written += mem::size_of::<TimeSpec>();
        }

        Ok(bytes_written)
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let clock = *HANDLES.read().get(&id).ok_or(Error::new(EBADF))?;

        let scheme_path = format!("time:{}", clock).into_bytes();
        buf.copy_common_bytes_from_slice(&scheme_path)
    }
}
