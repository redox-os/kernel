//! PS/2 unfortunately requires a kernel driver to prevent race conditions due
//! to how status is utilized
use core::{
    str,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    event,
    scheme::*,
    sync::{CleanLockToken, RwLock, WaitQueue, L1},
    syscall::{
        flag::{EventFlags, EVENT_READ, O_NONBLOCK},
        usercopy::UserSliceWo,
    },
};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Input queue
static INPUT: [WaitQueue<u8>; 2] = [WaitQueue::new(), WaitQueue::new()];

#[derive(Clone, Copy)]
struct Handle {
    index: usize,
}

static HANDLES: RwLock<L1, HashMap<usize, Handle>> =
    RwLock::new(HashMap::with_hasher(DefaultHashBuilder::new()));

/// Add to the input queue
pub fn serio_input(index: usize, data: u8, token: &mut CleanLockToken) {
    crate::profiling::serio_command(index, data);

    INPUT[index].send(data, token);

    for (id, _handle) in HANDLES.read(token.token()).iter() {
        event::trigger(GlobalSchemes::Serio.scheme_id(), *id, EVENT_READ);
    }
}

pub struct SerioScheme;

impl KernelScheme for SerioScheme {
    fn kopen(
        &self,
        path: &str,
        _flags: usize,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        if ctx.uid != 0 {
            return Err(Error::new(EPERM));
        }

        let index = path.parse::<usize>().or(Err(Error::new(ENOENT)))?;
        if index >= INPUT.len() {
            return Err(Error::new(ENOENT));
        }

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        HANDLES.write(token.token()).insert(id, Handle { index });

        Ok(OpenResult::SchemeLocal(id, InternalFlags::empty()))
    }

    fn fevent(
        &self,
        id: usize,
        _flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        let _handle = {
            let handles = HANDLES.read(token.token());
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(EventFlags::empty())
    }

    fn fsync(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        let _handle = {
            let handles = HANDLES.read(token.token());
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(())
    }

    /// Close the file `number`
    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        let _handle = {
            let mut handles = HANDLES.write(token.token());
            handles.remove(&id).ok_or(Error::new(EBADF))?
        };

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
        let handle = {
            let handles = HANDLES.read(token.token());
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        INPUT[handle.index].receive_into_user(
            buf,
            flags & O_NONBLOCK as u32 == 0,
            "SerioScheme::read",
            token,
        )
    }

    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        let handle = {
            let handles = HANDLES.read(token.token());
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };
        let path = format!("serio:{}", handle.index).into_bytes();

        buf.copy_common_bytes_from_slice(&path)
    }
}
