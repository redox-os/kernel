use alloc::vec::Vec;
use core::{
    fmt, mem, str,
    sync::atomic::{AtomicUsize, Ordering},
};
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};

use crate::{
    context::{file::InternalFlags, timeout},
    sync::{CleanLockToken, RwLock, L1},
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
static HANDLES: RwLock<L1, HashMap<usize, TimeSchemeHandle>> =
    RwLock::new(HashMap::with_hasher(DefaultHashBuilder::new()));

pub struct TimeScheme;

#[derive(Clone)]
pub enum TimeSchemeKind {
    Default,
    ClockGettime,
    ClockGetres,
    Timer,
}

impl fmt::Display for TimeSchemeKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TimeSchemeKind::Default => write!(f, ""),
            TimeSchemeKind::ClockGettime => write!(f, "gettime"),
            TimeSchemeKind::ClockGetres => write!(f, "getres"),
            TimeSchemeKind::Timer => write!(f, "timer"),
        }
    }
}

#[derive(Clone)]
pub struct TimeSchemeHandle {
    clock: usize,
    kind: TimeSchemeKind,
}

impl KernelScheme for TimeScheme {
    fn kopen(
        &self,
        path: &str,
        _flags: usize,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let path_parts: Vec<&str> = path.split("/").collect();
        let clock = path_parts[0]
            .parse::<usize>()
            .map_err(|_| Error::new(ENOENT))?;
        let kind = match path_parts.get(1).map(|e| e.as_ref()) {
            None | Some("") => TimeSchemeKind::Default,
            Some("gettime") => TimeSchemeKind::ClockGettime,
            Some("getres") => TimeSchemeKind::ClockGetres,
            Some("timer") => TimeSchemeKind::Timer,
            Some(_) => return Err(Error::new(ENOENT)),
        };

        match clock {
            CLOCK_REALTIME => (),
            CLOCK_MONOTONIC => (),
            _ => return Err(Error::new(ENOENT)),
        }

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        HANDLES
            .write(token.token())
            .insert(id, TimeSchemeHandle { clock, kind });

        Ok(OpenResult::SchemeLocal(id, InternalFlags::empty()))
    }

    fn fcntl(
        &self,
        _id: usize,
        _cmd: usize,
        _arg: usize,
        _token: &mut CleanLockToken,
    ) -> Result<usize> {
        Ok(0)
    }

    fn fevent(
        &self,
        id: usize,
        _flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))
            .and(Ok(EventFlags::empty()))
    }

    fn fsync(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?;
        Ok(())
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        HANDLES
            .write(token.token())
            .remove(&id)
            .ok_or(Error::new(EBADF))
            .and(Ok(()))
    }
    fn kread(
        &self,
        id: usize,
        buf: UserSliceWo,
        _flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?
            .clone();

        let mut bytes_read = 0;

        for current_chunk in buf.in_exact_chunks(mem::size_of::<TimeSpec>()) {
            let arch_time = match (handle.clock.clone(), handle.kind.clone()) {
                (CLOCK_REALTIME, TimeSchemeKind::Default | TimeSchemeKind::ClockGettime) => {
                    time::realtime()
                }
                (CLOCK_MONOTONIC, TimeSchemeKind::Default | TimeSchemeKind::ClockGettime) => {
                    time::monotonic()
                }
                (CLOCK_REALTIME, TimeSchemeKind::ClockGetres) => time::realtime_resolution(),
                (CLOCK_MONOTONIC, TimeSchemeKind::ClockGetres) => time::monotonic_resolution(),
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
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?
            .clone();

        let mut bytes_written = 0;

        for current_chunk in buf.in_exact_chunks(mem::size_of::<TimeSpec>()) {
            let time = unsafe { current_chunk.read_exact::<TimeSpec>()? };

            match (handle.clock.clone(), handle.kind.clone()) {
                (_, TimeSchemeKind::Default | TimeSchemeKind::Timer) => {
                    timeout::register(
                        GlobalSchemes::Time.scheme_id(),
                        id,
                        handle.clock,
                        time,
                        token,
                    );
                }
                _ => return Err(Error::new(EINVAL)),
            };

            bytes_written += mem::size_of::<TimeSpec>();
        }

        Ok(bytes_written)
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        let handle = HANDLES
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?
            .clone();

        let scheme_path = format!("/scheme/time/{}/{}", handle.clock, handle.kind).into_bytes();
        buf.copy_common_bytes_from_slice(&scheme_path)
    }
}
