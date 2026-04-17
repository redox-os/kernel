use alloc::vec::Vec;
use core::{fmt, str};
use syscall::data::GlobalSchemes;

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

use super::{CallerCtx, HandleMap, KernelScheme, OpenResult, SchemeExt, StrOrBytes};

#[derive(Clone)]
enum Handle {
    SchemeRoot,
    Clock(TimeSchemeHandle),
}

static HANDLES: RwLock<L1, HandleMap<Handle>> = RwLock::new(HandleMap::new());

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
    fn scheme_root(&self, token: &mut CleanLockToken) -> Result<usize> {
        let id = HANDLES.write(token.token()).insert(Handle::SchemeRoot);
        Ok(id)
    }
    fn kopenat(
        &self,
        id: usize,
        user_buf: StrOrBytes,
        _flags: usize,
        _fcntl_flags: u32,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        {
            let handles = HANDLES.read(token.token());
            let handle = handles.get(id)?;

            if !matches!(handle, Handle::SchemeRoot) {
                return Err(Error::new(EACCES));
            }
        }

        let path = user_buf.as_str().or(Err(Error::new(EINVAL)))?;
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

        let id = HANDLES
            .write(token.token())
            .insert(Handle::Clock(TimeSchemeHandle { clock, kind }));

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
            .get(id)
            .and(Ok(EventFlags::empty()))
    }

    fn fsync(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        HANDLES.read(token.token()).get(id)?;
        Ok(())
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        HANDLES.write(token.token()).remove(id).and(Ok(()))
    }
    fn kread(
        &self,
        id: usize,
        buf: UserSliceWo,
        _flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = match HANDLES.read(token.token()).get(id)? {
            Handle::Clock(handle) => handle.clone(),
            Handle::SchemeRoot => return Err(Error::new(EBADF)),
        };

        let mut bytes_read = 0;

        for current_chunk in buf.in_exact_chunks(size_of::<TimeSpec>()) {
            let arch_time = match (handle.clock, handle.kind.clone()) {
                (CLOCK_REALTIME, TimeSchemeKind::Default | TimeSchemeKind::ClockGettime) => {
                    time::realtime(token)
                }
                (CLOCK_MONOTONIC, TimeSchemeKind::Default | TimeSchemeKind::ClockGettime) => {
                    time::monotonic(token)
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

            bytes_read += size_of::<TimeSpec>();
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
        let handle = match HANDLES.read(token.token()).get(id)? {
            Handle::Clock(handle) => handle.clone(),
            Handle::SchemeRoot => return Err(Error::new(EBADF)),
        };

        let mut bytes_written = 0;

        for current_chunk in buf.in_exact_chunks(size_of::<TimeSpec>()) {
            let time = unsafe { current_chunk.read_exact::<TimeSpec>()? };

            match (handle.clock, handle.kind.clone()) {
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

            bytes_written += size_of::<TimeSpec>();
        }

        Ok(bytes_written)
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        let handle = match HANDLES.read(token.token()).get(id)? {
            Handle::Clock(handle) => handle.clone(),
            Handle::SchemeRoot => return Err(Error::new(EBADF)),
        };

        let scheme_path = format!("/scheme/time/{}/{}", handle.clock, handle.kind).into_bytes();
        buf.copy_common_bytes_from_slice(&scheme_path)
    }
}
