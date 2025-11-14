use alloc::sync::Arc;
use core::mem;
use syscall::{EventFlags, O_NONBLOCK};

use crate::{
    context::file::InternalFlags,
    event::{next_queue_id, queues, queues_mut, EventQueue, EventQueueId},
    sync::CleanLockToken,
    syscall::{
        data::Event,
        error::*,
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

use super::{CallerCtx, KernelScheme, OpenResult};

pub struct EventScheme;

impl KernelScheme for EventScheme {
    fn kopen(
        &self,
        _path: &str,
        _flags: usize,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let id = next_queue_id();
        queues_mut(token.token()).insert(id, Arc::new(EventQueue::new(id)));

        Ok(OpenResult::SchemeLocal(id.get(), InternalFlags::empty()))
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        let id = EventQueueId::from(id);
        queues_mut(token.token())
            .remove(&id)
            .ok_or(Error::new(EBADF))
            .and(Ok(()))
    }

    fn kread(
        &self,
        id: usize,
        buf: UserSliceWo,
        flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let id = EventQueueId::from(id);

        let queue = {
            let handles = queues(token.token());
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        queue.read(buf, flags & O_NONBLOCK as u32 == 0, token)
    }

    fn kwrite(
        &self,
        id: usize,
        buf: UserSliceRo,
        _flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let id = EventQueueId::from(id);

        let queue = {
            let handles = queues(token.token());
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };
        let mut events_written = 0;

        for chunk in buf.in_exact_chunks(mem::size_of::<Event>()) {
            let event = unsafe { chunk.read_exact::<Event>()? };
            if queue.write(&[event], token)? == 0 {
                break;
            }
            events_written += 1;
        }

        Ok(events_written * mem::size_of::<Event>())
    }

    fn kfpath(&self, _id: usize, buf: UserSliceWo, _token: &mut CleanLockToken) -> Result<usize> {
        buf.copy_common_bytes_from_slice(b"/scheme/event/")
    }

    fn fevent(
        &self,
        id: usize,
        flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        let id = EventQueueId::from(id);

        let queue = {
            let handles = queues(token.token());
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        let mut ready = EventFlags::empty();
        if flags.contains(EventFlags::EVENT_WRITE) {
            // It is always possible to write events
            ready |= EventFlags::EVENT_WRITE;
        }
        if flags.contains(EventFlags::EVENT_READ) && !queue.is_currently_empty() {
            // It is possible to read if queue is not empty
            ready |= EventFlags::EVENT_READ;
        }
        Ok(ready)
    }
}
