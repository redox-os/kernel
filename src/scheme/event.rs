use alloc::sync::Arc;
use core::mem;
use syscall::O_NONBLOCK;

use crate::{
    context::file::InternalFlags,
    event::{next_queue_id, queues, queues_mut, EventQueue, EventQueueId},
    syscall::{
        data::Event,
        error::*,
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

use super::{CallerCtx, KernelScheme, OpenResult};

pub struct EventScheme;

impl KernelScheme for EventScheme {
    fn kopen(&self, _path: &str, _flags: usize, _ctx: CallerCtx) -> Result<OpenResult> {
        let id = next_queue_id();
        queues_mut().insert(id, Arc::new(EventQueue::new(id)));

        Ok(OpenResult::SchemeLocal(id.get(), InternalFlags::empty()))
    }

    fn close(&self, id: usize) -> Result<()> {
        let id = EventQueueId::from(id);
        queues_mut()
            .remove(&id)
            .ok_or(Error::new(EBADF))
            .and(Ok(()))
    }
    fn kread(&self, id: usize, buf: UserSliceWo, flags: u32, _stored_flags: u32) -> Result<usize> {
        let id = EventQueueId::from(id);

        let queue = {
            let handles = queues();
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        queue.read(buf, flags & O_NONBLOCK as u32 == 0)
    }

    fn kwrite(
        &self,
        id: usize,
        buf: UserSliceRo,
        _flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        let id = EventQueueId::from(id);

        let queue = {
            let handles = queues();
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };
        let mut events_written = 0;

        for chunk in buf.in_exact_chunks(mem::size_of::<Event>()) {
            let event = unsafe { chunk.read_exact::<Event>()? };
            if queue.write(&[event])? == 0 {
                break;
            }
            events_written += 1;
        }

        Ok(events_written * mem::size_of::<Event>())
    }

    fn kfpath(&self, _id: usize, buf: UserSliceWo) -> Result<usize> {
        buf.copy_common_bytes_from_slice(b"event:")
    }
}
