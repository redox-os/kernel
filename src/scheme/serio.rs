//! PS/2 unfortunately requires a kernel driver to prevent race conditions due
//! to how status is utilized

use syscall::data::GlobalSchemes;

use crate::{
    event,
    scheme::*,
    sync::{CleanLockToken, RwLock, WaitQueue, L1},
    syscall::{
        flag::{EventFlags, EVENT_READ, O_NONBLOCK},
        usercopy::UserSliceWo,
    },
};

use super::StrOrBytes;

/// Input queue
static INPUT: [WaitQueue<u8>; 2] = [WaitQueue::new(), WaitQueue::new()];

#[derive(Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    Device(usize),
    SchemeRoot,
}

#[derive(Clone, Copy)]
struct Handle {
    kind: HandleKind,
}

static HANDLES: RwLock<L1, HandleMap<Handle>> = RwLock::new(HandleMap::new());

/// Add to the input queue
pub fn serio_input(index: usize, data: u8, token: &mut CleanLockToken) {
    crate::profiling::serio_command(index, data);

    INPUT[index].send(data, token);

    let ids: Vec<usize> = {
        HANDLES
            .read(token.token())
            .iter()
            .map(|(id, _)| *id)
            .collect()
    };

    for id in ids {
        event::trigger(GlobalSchemes::Serio.scheme_id(), id, EVENT_READ, token);
    }
}

pub struct SerioScheme;

impl KernelScheme for SerioScheme {
    fn scheme_root(&self, token: &mut CleanLockToken) -> Result<usize> {
        let id = HANDLES.write(token.token()).insert(Handle {
            kind: HandleKind::SchemeRoot,
        });
        Ok(id)
    }

    fn kopenat(
        &self,
        id: usize,
        user_buf: StrOrBytes,
        _flags: usize,
        _fcntl_flags: u32,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        {
            let handles = HANDLES.read(token.token());
            let handle = handles.get(id)?;

            if !matches!(handle.kind, HandleKind::SchemeRoot) {
                return Err(Error::new(EACCES));
            }
        }

        let path = user_buf.as_str().or(Err(Error::new(EINVAL)))?;
        if ctx.uid != 0 {
            return Err(Error::new(EPERM));
        }

        let index = path.parse::<usize>().or(Err(Error::new(ENOENT)))?;
        if index >= INPUT.len() {
            return Err(Error::new(ENOENT));
        }

        let id = HANDLES.write(token.token()).insert(Handle {
            kind: HandleKind::Device(index),
        });

        Ok(OpenResult::SchemeLocal(id, InternalFlags::empty()))
    }

    fn fevent(
        &self,
        id: usize,
        _flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        let handles = HANDLES.read(token.token());
        let handle = handles.get(id)?;

        if let HandleKind::Device(_) = handle.kind {
            Ok(EventFlags::empty())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fsync(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        HANDLES.read(token.token()).get(id)?;
        Ok(())
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        HANDLES.write(token.token()).remove(id)?;
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
        let handle = *HANDLES.read(token.token()).get(id)?;

        let index = match handle.kind {
            HandleKind::Device(index) => index,
            HandleKind::SchemeRoot => return Err(Error::new(EBADF)),
        };

        INPUT[index].receive_into_user(
            buf,
            flags & O_NONBLOCK as u32 == 0,
            "SerioScheme::read",
            token,
        )
    }

    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        let handle = *HANDLES.read(token.token()).get(id)?;

        let path = match handle.kind {
            HandleKind::Device(index) => format!("serio:{}", index).into_bytes(),
            HandleKind::SchemeRoot => return Err(Error::new(EBADF)),
        };

        buf.copy_common_bytes_from_slice(&path)
    }
}
