use alloc::collections::BTreeMap;
use core::{mem, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use crate::syscall::data::ITimerSpec;
use crate::syscall::error::*;
use crate::syscall::flag::{CLOCK_REALTIME, CLOCK_MONOTONIC, EventFlags};
use crate::syscall::scheme::Scheme;
use crate::syscall::usercopy::{UserSliceWo, UserSliceRo};

pub struct ITimerScheme {
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, usize>>
}

impl ITimerScheme {
    pub fn new() -> ITimerScheme {
        ITimerScheme {
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new())
        }
    }
}

impl Scheme for ITimerScheme {
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

    fn fevent(&self, id: usize, _flags: EventFlags) ->  Result<EventFlags> {
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
impl crate::scheme::KernelScheme for ITimerScheme {
    fn kread(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let _clock = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut specs_read = 0;

        for current_chunk in buf.in_exact_chunks(mem::size_of::<ITimerScheme>()) {
            current_chunk.copy_exactly(&ITimerSpec::default())?;

            specs_read += 1;
        }

        Ok(specs_read * mem::size_of::<ITimerSpec>())
    }

    fn kwrite(&self, id: usize, buf: UserSliceRo) -> Result<usize> {
        let _clock = {
            let handles = self.handles.read();
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
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        buf.copy_common_bytes_from_slice(format!("time:{}", clock).as_bytes())
    }

}
