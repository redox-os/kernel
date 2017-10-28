use alloc::arc::{Arc, Weak};
use alloc::BTreeMap;
use core::{mem, slice};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use context;
use sync::WaitQueue;
use syscall::data::Event;
use syscall::error::*;
use syscall::scheme::Scheme;

pub struct EventScheme {
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, Weak<WaitQueue<Event>>>>
}

impl EventScheme {
    pub fn new() -> EventScheme {
        EventScheme {
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new())
        }
    }
}

impl Scheme for EventScheme {
    fn open(&self, _path: &[u8], _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let handle = {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();
            context.events.clone()
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.handles.write().insert(id, Arc::downgrade(&handle));

        Ok(id)
    }

    fn dup(&self, id: usize, buf: &[u8]) -> Result<usize> {
        if ! buf.is_empty() {
            return Err(Error::new(EINVAL));
        }

        let handle = {
            let handles = self.handles.read();
            let handle_weak = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle_weak.upgrade().ok_or(Error::new(EBADF))?
        };

        let new_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.handles.write().insert(new_id, Arc::downgrade(&handle));
        Ok(new_id)
    }

    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle_weak = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle_weak.upgrade().ok_or(Error::new(EBADF))?
        };

        let event_buf = unsafe { slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut Event, buf.len()/mem::size_of::<Event>()) };
        Ok(handle.receive_into(event_buf, true) * mem::size_of::<Event>())
    }

    fn fcntl(&self, id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        let handles = self.handles.read();
        let handle_weak = handles.get(&id).ok_or(Error::new(EBADF))?;
        handle_weak.upgrade().ok_or(Error::new(EBADF)).and(Ok(0))
    }

    fn fpath(&self, _id: usize, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        let scheme_path = b"event:";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }
        Ok(i)
    }

    fn fsync(&self, id: usize) -> Result<usize> {
        let handles = self.handles.read();
        let handle_weak = handles.get(&id).ok_or(Error::new(EBADF))?;
        handle_weak.upgrade().ok_or(Error::new(EBADF)).and(Ok(0))
    }

    fn close(&self, id: usize) -> Result<usize> {
        self.handles.write().remove(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
