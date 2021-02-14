use alloc::sync::Arc;
use core::{mem, slice};

use crate::event::{EventQueue, EventQueueId, next_queue_id, queues, queues_mut};
use crate::syscall::data::Event;
use crate::syscall::error::*;
use crate::syscall::scheme::Scheme;

pub struct EventScheme;

impl Scheme for EventScheme {
    fn open(&self, _path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let id = next_queue_id();
        queues_mut().insert(id, Arc::new(EventQueue::new(id)));

        Ok(id.into())
    }

    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let id = EventQueueId::from(id);

        let queue = {
            let handles = queues();
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        let event_buf = unsafe { slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut Event, buf.len()/mem::size_of::<Event>()) };
        Ok(queue.read(event_buf)? * mem::size_of::<Event>())
    }

    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        let id = EventQueueId::from(id);

        let queue = {
            let handles = queues();
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        let event_buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const Event, buf.len()/mem::size_of::<Event>()) };
        Ok(queue.write(event_buf)? * mem::size_of::<Event>())
    }

    fn fcntl(&self, id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        let id = EventQueueId::from(id);

        let handles = queues();
        handles.get(&id).ok_or(Error::new(EBADF)).and(Ok(0))
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
        let id = EventQueueId::from(id);

        let handles = queues();
        handles.get(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }

    fn close(&self, id: usize) -> Result<usize> {
        let id = EventQueueId::from(id);
        queues_mut().remove(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
