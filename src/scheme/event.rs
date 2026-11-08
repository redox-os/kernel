use alloc::sync::Arc;
use syscall::{data::FdType, CapRights, EventFlags, O_NONBLOCK};

use crate::{
    context::file::InternalFlags,
    event::{next_queue_id, queues, queues_mut, unregister_queue, EventQueue, EventQueueId},
    sync::CleanLockToken,
    syscall::{
        data::Event,
        error::*,
        usercopy::{UserSliceRo, UserSliceRw, UserSliceWo},
    },
};

use super::{CallerCtx, KernelScheme, OpenResult, StrOrBytes};

const SCHEME_ROOT_ID: usize = usize::MAX;

pub struct EventScheme;

impl KernelScheme for EventScheme {
    fn scheme_root(&self, _token: &mut CleanLockToken) -> Result<usize> {
        Ok(SCHEME_ROOT_ID)
    }
    fn kopenat(
        &self,
        id: usize,
        _user_buf: StrOrBytes,
        _flags: usize,
        _fcntl_flags: u32,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        if id != SCHEME_ROOT_ID {
            return Err(Error::new(EACCES));
        }
        let id = next_queue_id();
        queues_mut(token.token()).insert(id, Arc::new(EventQueue::new(id)));

        Ok(OpenResult::SchemeLocal(
            id.get(),
            InternalFlags::empty(),
            CapRights::ALL,
            FdType::default(),
        ))
    }

    fn kcall(
        &self,
        fds: &[usize],
        payload: UserSliceRw,
        _flags: syscall::CallFlags,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        if fds.len() != 1 {
            return Err(Error::new(EINVAL));
        }

        let id = EventQueueId::from(fds[0]);
        let queue = {
            let handles = queues(token.token());
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        // metadata[0] = RSVDZ
        // metadata[1] = event length in bytes
        // metadata[2] = read flags
        let (Some(_protocol), Some(write_len), Some(read_flags)) = (
            metadata.get(0).filter(|&&p| p == 0),
            metadata.get(1).copied().map(|s| s as usize),
            metadata.get(2).copied().map(|s| s as usize),
        ) else {
            return Err(Error::new(EINVAL));
        };

        let (input_slice, output_slice) = payload.split_at(write_len).ok_or(Error::new(EINVAL))?;

        let mut nval_count = 0;
        let mut output_remain = output_slice.into_wo()?;

        if write_len > 0 {
            for chunk in input_slice.in_exact_chunks(size_of::<Event>()) {
                let event = unsafe { chunk.read_exact::<Event>()? };

                match queue.write(&[event], token) {
                    Ok(_) => {}
                    Err(e) if e.errno == EBADF => {
                        let nval_event = Event {
                            id: event.id,
                            flags: EventFlags::EVENT_NVAL,
                            data: event.data,
                        };

                        let chunk_wo = output_remain
                            .limit(size_of::<Event>())
                            .ok_or(Error::new(EFAULT))?;
                        unsafe { chunk_wo.copy_from_slice(&nval_event)? };

                        output_remain = output_remain
                            .advance(size_of::<Event>())
                            .ok_or(Error::new(EFAULT))?;
                        nval_count += 1;
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // nval must be reported immediately
        let block = read_flags & O_NONBLOCK == 0 && nval_count == 0;

        let bytes_read = match queue.read(output_remain, block, token) {
            Ok(bytes) => bytes,
            Err(Error { errno: EAGAIN }) => return Ok(nval_count * size_of::<Event>()),
            Err(e) => return Err(e),
        };
        let total_bytes_out = (nval_count * size_of::<Event>()) + bytes_read;

        if write_len > 0 {
            for chunk in input_slice.in_exact_chunks(size_of::<Event>()) {
                if let Ok(mut event) = unsafe { chunk.read_exact::<Event>() } {
                    event.flags = EventFlags::empty();
                    let _ = queue.write(&[event], token);
                }
            }
        }
        Ok(total_bytes_out)
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        let id = EventQueueId::from(id);
        unregister_queue(id, token);
        let queue = queues_mut(token.token())
            .remove(&id)
            .ok_or(Error::new(EBADF))?;
        if let Some(queue) = Arc::into_inner(queue) {
            queue.into_drop(token.downgrade());
        }
        Ok(())
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

        for chunk in buf.in_exact_chunks(size_of::<Event>()) {
            let event = unsafe { chunk.read_exact::<Event>()? };
            if queue.write(&[event], token)? == 0 {
                break;
            }
            events_written += 1;
        }

        Ok(events_written * size_of::<Event>())
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
        if flags.contains(EventFlags::EVENT_READ) && !queue.is_currently_empty(token) {
            // It is possible to read if queue is not empty
            ready |= EventFlags::EVENT_READ;
        }
        Ok(ready)
    }
}
