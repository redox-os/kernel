use alloc::collections::BTreeMap;
use core::{
    mem, str,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::RwLock;

use crate::{
    context::file::InternalFlags,
    syscall::{
        data::ITimerSpec,
        error::*,
        flag::{EventFlags, CLOCK_MONOTONIC, CLOCK_REALTIME},
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

use super::{CallerCtx, KernelScheme, OpenResult};
pub struct ITimerScheme;

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
// Using BTreeMap as hashbrown doesn't have a const constructor.
static HANDLES: RwLock<BTreeMap<usize, usize>> = RwLock::new(BTreeMap::new());

impl KernelScheme for ITimerScheme {
    fn kopen(&self, path: &str, _flags: usize, _ctx: CallerCtx) -> Result<OpenResult> {
        let clock = path.parse::<usize>().or(Err(Error::new(ENOENT)))?;

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
        let handles = HANDLES.read();
        handles
            .get(&id)
            .ok_or(Error::new(EBADF))
            .and(Ok(EventFlags::empty()))
    }

    fn fsync(&self, id: usize) -> Result<()> {
        HANDLES.read().get(&id).ok_or(Error::new(EBADF)).and(Ok(()))
    }

    fn close(&self, id: usize) -> Result<()> {
        HANDLES
            .write()
            .remove(&id)
            .ok_or(Error::new(EBADF))
            .and(Ok(()))
    }
    fn kread(&self, id: usize, buf: UserSliceWo, _flags: u32, _stored_flags: u32) -> Result<usize> {
        let _clock = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut specs_read = 0;

        for current_chunk in buf.in_exact_chunks(mem::size_of::<ITimerScheme>()) {
            current_chunk.copy_exactly(&ITimerSpec::default())?;

            specs_read += 1;
        }

        Ok(specs_read * mem::size_of::<ITimerSpec>())
    }

    fn kwrite(
        &self,
        id: usize,
        buf: UserSliceRo,
        _flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        let _clock = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut specs_written = 0;

        for chunk in buf.in_exact_chunks(mem::size_of::<ITimerSpec>()) {
            let time = unsafe { chunk.read_exact::<ITimerSpec>()? };

            println!("{}: {:?}", specs_written, time);
            specs_written += 1;
        }

        Ok(specs_written * mem::size_of::<ITimerSpec>())
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let clock = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        buf.copy_common_bytes_from_slice(format!("time:{}", clock).as_bytes())
    }
}
